import streamlit as st
import pandas as pd
import numpy as np
from math import sqrt
from scapy.all import sniff, IP, TCP, UDP,ICMP, Raw, rdpcap
import socket
from datetime import datetime
import matplotlib.pyplot as plt
from joblib import load
import os
import ipaddress
import time
import threading
from collections import defaultdict, deque
import psutil #detecter les Ifaces

#1) CONFIGURATION  GENERALE
# IMPORTANT : adaptez l'ordre et les noms ci-dessous à VOTRE modèle (exactement 42 colonnes

FEATURE_COLUMNS = [
    # --- A. Basique/entête & metadata flux ---
    "duration",
    "src_bytes", "dst_bytes",
    "packets_fwd", "packets_bwd",
    "pkt_size_mean", "pkt_size_std",
    "iat_mean", "iat_std",  # Inter-Arrival Time (ms)
    "tcp_syn", "tcp_ack", "tcp_fin", "tcp_rst",

    # --- B. One-hot protocol/service (adaptez à votre entraînement !) ---
    "protocol_type_tcp", "protocol_type_udp", "protocol_type_other",
    "service_http", "service_https", "service_dns", "service_ssh",
    "service_ftp", "service_smtp", "service_other",

    # --- C. Ratios / taux d'erreurs / LAN indicators ---
    "fwd_bwd_ratio_bytes", "fwd_bwd_ratio_pkts",
    "same_srv_rate", "diff_srv_rate",
    "srv_count_2s", "host_count_2s",
    "serror_rate", "rerror_rate",

    # --- D. Flags dérivés / booléens (style KDD-like simplifiés) ---
    "land",  # src==dst and src_port==dst_port
    "has_payload",  # présence d'un payload applicatif
    "small_flow",   # moins de 3 paquets
    "long_flow",    # durée > seuil
    "high_pkt_rate",# > X pkts/s
    "high_byte_rate",# > X bytes/s

    # --- E. Ports sensibles (facultatif mais fréquent en LAN) ---
    "port_is_privileged",    # dst_port < 1024
    "dst_is_broadcast",      # dst IP broadcast
    "src_internal",          # RFC1918
    "dst_internal",          # RFC1918
    "arp_suspect"            # (placeholder si vous intégrez ARP parsing ailleurs)
]
assert len(FEATURE_COLUMNS) == 42, f"{len(FEATURE_COLUMNS)} #colonnes définies, il en faut 42 exactement"

# === Charger le modèle IA entraîné ===
MODEL_PATH ="ids_model.pkl"
#model = load(MODEL_PATH) if os.path.exists(MODEL_PATH) else None
model ="ids_model.pkl"

# 2) OUTILS & MAPPINGS
SERVICE_PORTS = {
    "http": 80,
    "https": 443,
    "dns": 53,
    "ssh": 22,
    "ftp": 21,
    "smtp": 25,
}
PRIVATE_NETS = [
    ("10.",), ("172.", "16-31"), ("192.168.",),("127.0.0.0/8","LoopBack"),("169.254.0.0/16","LinkLocal"),
    ("fc00::/7","UniqueLocal"),("fe80::/10","LinkLocal"), ("::1/128","LoopBack"),("::ffff:0:0/96","IPv4Mapped"),
    ("::/128","Unspecified"),("ff00::/8","Multicast"),("2001:db8::/32","Documentation"),("2001::/23","Teredo"),("2002::/16","6to4"),
    ("2001:10::/28","ORCHID"),("2001:20::/28","ORCHIDv2"),("2001:2::/48","Benchmarking"),("2001:3::/32","AMT"),("2001:4:112::/48","AS112"),
    ("2001:5::/32","NAT64/DNS64"),("2001:6::/32","Homenet"),("2001:7::/32","NAT64/DNS64"),("2001:db8::/32","Documentation"),("100.64.0.0/10","Operateur")
]

def is_internal_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False

    # Choix courant : considérer privées + loopback + link-local comme "internes"
    return addr.is_private or addr.is_loopback or addr.is_link_local

def guess_service(dst_port: int, proto: str = None) -> str:
    if proto == "ICMP":
        return "icmp"
    for name, port in SERVICE_PORTS.items():
        if dst_port == port:
            return name
    return "other"

def now_ms():
    return int(time.time() * 1000)

# 3) ETAT DES FLUX
class Flow:
    __slots__ = ("src","dst","sport","dport","proto",
                 "first_ts","last_ts",
                 "bytes_fwd","bytes_bwd","pkts_fwd","pkts_bwd",
                 "sizes","times",
                 "syn","ack","fin","rst",
                 "payload_count")

    def __init__(self, src, dst, sport, dport, proto, ts_ms):
        self.src, self.dst, self.sport, self.dport, self.proto = src, dst, sport, dport, proto
        self.first_ts = ts_ms
        self.last_ts  = ts_ms
        self.bytes_fwd = 0
        self.bytes_bwd = 0
        self.pkts_fwd = 0
        self.pkts_bwd = 0
        self.sizes = []    # tailles de paquets du flux
        self.times = []    # timestamps (ms) des paquets
        self.syn = self.ack = self.fin = self.rst = 0
        self.payload_count = 0

    def update(self, direction: str, length: int, flags: dict, ts_ms: int, has_payload: bool):
        self.last_ts = ts_ms
        if direction == "fwd":
            self.bytes_fwd += length
            self.pkts_fwd  += 1
        else:
            self.bytes_bwd += length
            self.pkts_bwd  += 1
        self.sizes.append(length)
        self.times.append(ts_ms)
        # flags
        if flags.get("SYN"): self.syn += 1
        if flags.get("ACK"): self.ack += 1
        if flags.get("FIN"): self.fin += 1
        if flags.get("RST"): self.rst += 1
        if has_payload: self.payload_count += 1

    def to_features(self, window_stats) -> dict:
        duration_ms = max(1, self.last_ts - self.first_ts)
        duration = duration_ms / 1000.0

        pkt_mean = float(np.mean(self.sizes)) if self.sizes else 0.0
        pkt_std  = float(np.std(self.sizes)) if len(self.sizes) > 1 else 0.0

        iats = np.diff(self.times) if len(self.times) > 1 else []
        iat_mean = float(np.mean(iats)) if len(iats) else 0.0
        iat_std  = float(np.std(iats)) if len(iats) > 1 else 0.0

        fwd_bwd_ratio_bytes = (self.bytes_fwd + 1) / (self.bytes_bwd + 1)
        fwd_bwd_ratio_pkts  = (self.pkts_fwd + 1) / (self.pkts_bwd + 1)

        # One-hot protocol
        proto_tcp = 1 if self.proto == "TCP" else 0
        proto_udp = 1 if self.proto == "UDP" else 0
        proto_other = 1 if self.proto not in ("TCP","UDP") else 0

        # One-hot service (via port destination)
        service = guess_service(self.dport,self.proto)
        service_map = {k: 0 for k in ["http","https","dns","ssh","ftp","smtp","other"]}
        service_map[service] = 1

        # Fenêtre 2s (stats de voisinage pour ce même hôte/service)
        same_srv_rate = window_stats.get("same_srv_rate", 0.0)
        diff_srv_rate = window_stats.get("diff_srv_rate", 0.0)
        srv_count_2s  = window_stats.get("srv_count_2s", 0)
        host_count_2s = window_stats.get("host_count_2s", 0)
        serror_rate   = window_stats.get("serror_rate", 0.0)
        rerror_rate   = window_stats.get("rerror_rate", 0.0)

        land = int(self.src == self.dst and self.sport == self.dport)
        has_payload = int(self.payload_count > 0)
        small_flow  = int((self.pkts_fwd + self.pkts_bwd) < 3)
        long_flow   = int(duration > 10.0)                # seuil 10s (adaptez)
        pkt_rate    = (self.pkts_fwd + self.pkts_bwd) / duration if duration > 0 else 0
        byte_rate   = (self.bytes_fwd + self.bytes_bwd) / duration if duration > 0 else 0
        high_pkt_rate  = int(pkt_rate  > 200)             # seuils à ajuster selon LAN
        high_byte_rate = int(byte_rate > 200000)          # ~200KB/s (exemple)

        port_is_privileged = int(self.dport < 1024)
        dst_is_broadcast   = int(self.dst.endswith(".255"))  # simplification
        src_internal       = int(is_internal_ip(self.src))
        dst_internal       = int(is_internal_ip(self.dst))
        arp_suspect        = 0  # placeholder si vous ajoutez détection ARP ailleurs

        feat = {
            "duration": duration,
            "src_bytes": self.bytes_fwd,
            "dst_bytes": self.bytes_bwd,
            "packets_fwd": self.pkts_fwd,
            "packets_bwd": self.pkts_bwd,
            "pkt_size_mean": pkt_mean,
            "pkt_size_std": pkt_std,
            "iat_mean": iat_mean,
            "iat_std": iat_std,
            "tcp_syn": self.syn,
            "tcp_ack": self.ack,
            "tcp_fin": self.fin,
            "tcp_rst": self.rst,

            "protocol_type_tcp": proto_tcp,
            "protocol_type_udp": proto_udp,
            "protocol_type_other": proto_other,
            "service_http": service_map["http"],
            "service_https": service_map["https"],
            "service_dns": service_map["dns"],
            "service_ssh": service_map["ssh"],
            "service_ftp": service_map["ftp"],
            "service_smtp": service_map["smtp"],
            "service_other": service_map["other"],

            "fwd_bwd_ratio_bytes": fwd_bwd_ratio_bytes,
            "fwd_bwd_ratio_pkts": fwd_bwd_ratio_pkts,
            "same_srv_rate": same_srv_rate,
            "diff_srv_rate": diff_srv_rate,
            "srv_count_2s": srv_count_2s,
            "host_count_2s": host_count_2s,
            "serror_rate": serror_rate,
            "rerror_rate": rerror_rate,

            "land": land,
            "has_payload": has_payload,
            "small_flow": small_flow,
            "long_flow": long_flow,
            "high_pkt_rate": high_pkt_rate,
            "high_byte_rate": high_byte_rate,

            "port_is_privileged": port_is_privileged,
            "dst_is_broadcast": dst_is_broadcast,
            "src_internal": src_internal,
            "dst_internal": dst_internal,
            "arp_suspect": arp_suspect
        }
        return feat

# Dictionnaire des flux actifs
flows = {}
# file d'événements récents pour stats de fenêtre 2s
recent_events = deque(maxlen=5000)
lock = threading.Lock()

def flow_key(pkt):
    if IP in pkt:
        if TCP in pkt:
            proto = "TCP"
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
        elif UDP in pkt:
            proto = "UDP"
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)
        elif ICMP in pkt:
            proto = "ICMP"
            sport = 0
            dport = 0
        else:
            proto = "OTHER"
            sport = 0
            dport = 0
        src = pkt[IP].src
        dst = pkt[IP].dst
        return (src, dst, sport, dport, proto)
    return ("0.0.0.0", "0.0.0.0", 0, 0, "OTHER")

def window_stats_for(flow: Flow, ts_ms: int):
    # Stats simplifiées sur 2 secondes glissantes
    window_ms = 2000
    src, dst, _, dport, _ = flow.src, flow.dst, flow.sport, flow.dport, flow.proto
    service = guess_service(dport,flow.proto)
    same_srv = diff_srv = 0
    srv_count = 0
    hosts = set()
    syn_err = 0
    rst_err = 0
    total = 0

    with lock:
        # purge des anciens événements
        while recent_events and ts_ms - recent_events[0]["ts"] > window_ms:
            recent_events.popleft()

        for ev in recent_events:
            total += 1
            hosts.add(ev["dst"])
            srv_count += 1 if ev["service"] == service else 0
            if ev["service"] == service:
                same_srv += 1
            else:
                diff_srv += 1
            syn_err += 1 if ev.get("syn_err", False) else 0
            rst_err += 1 if ev.get("rst_err", False) else 0

    same_rate = (same_srv / total) if total else 0.0
    diff_rate = (diff_srv / total) if total else 0.0
    serror = (syn_err / total) if total else 0.0
    rerror = (rst_err / total) if total else 0.0

    return {
        "same_srv_rate": same_rate,
        "diff_srv_rate": diff_rate,
        "srv_count_2s": srv_count,
        "host_count_2s": len(hosts),
        "serror_rate": serror,
        "rerror_rate": rerror
    }

def _on_packet(pkt):
    try:
        if IP not in pkt:
            return
        ts_ms = now_ms()
        key = flow_key(pkt)
        direction = "fwd"  # simplifié (un sens : src->dst); vous pouvez inverser selon tuple
        length = int(len(pkt))
        flags = {}
        if TCP in pkt:
            tcp = pkt[TCP]
            flags = {
                "SYN": tcp.flags & 0x02 != 0,
                "ACK": tcp.flags & 0x10 != 0,
                "FIN": tcp.flags & 0x01 != 0,
                "RST": tcp.flags & 0x04 != 0
            }
        has_payload = Raw in pkt

        with lock:
            if key not in flows:
                if TCP in pkt:
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                    proto = "TCP"
                elif UDP in pkt:
                    sport = pkt[UDP].sport
                    dport = pkt[UDP].dport
                    proto = "UDP"
                elif ICMP in pkt:
                    sport = 0
                    dport = 0
                    proto = "ICMP"
                else:
                    sport = 0
                    dport = 0
                    proto = "OTHER"
                flows[key] = Flow(pkt[IP].src, pkt[IP].dst, sport, dport, proto, ts_ms)
            fl = flows[key]
            fl.update(direction, length, flags, ts_ms, has_payload)
            # événements pour fenêtre 2s
            recent_events.append({
                "ts": ts_ms,
                "dst": fl.dst,
                "service": guess_service(fl.dport,fl.proto),
                "syn_err": bool(flags.get("SYN") and flags.get("RST")), # très simplifié
                "rst_err": bool(flags.get("RST"))
            })
    except Exception as e:
        # Eviter que le thread plante silencieusement
        print("Packet error:", e)


def sniff_thread(iface, stop_event, count=0, bpf_filter=None):
    try:
        if iface and isinstance(iface, str):
            print(f"[INFO] Démarrage de la capture sur {iface}...")
            sniff(
                iface=iface,
                prn=_on_packet,
                store=False,
                filter=bpf_filter,
                stop_filter=lambda p: stop_event.is_set(),
                
            )
            print("[INFO] Capture terminée.")
        else:
            st.error("Interface invalide ou non sélectionnée.")
    except Exception as e:
        print(f"[ERREUR] Impossible de démarrer la capture : {e}")


captured_data = []

# === Interface Streamlit ===
st.set_page_config(layout="wide")
st.title("🛡️ IDS en temps réel avec Scapy + IA")
st.markdown("**📍 Position recommandée** : sur un port SPAN ou machine passerelle du réseau local.")
interfaces = list(psutil.net_if_addrs().keys())
with st.sidebar:
    st.header("Capture")
    iface = st.selectbox(
        "Interface réseau à utiliser pour la capture",
        options=interfaces,
        index=0  # sélectionne la première par défaut
    )
    start_btn = st.button("▶️ Démarrer la capture (30 paquets)")
    stop_btn = st.button("Arrêter")

    st.header("Modèle")
    st.write(f"Modèle chargé :")
    st.write(f"Scaler ")

if "capturing" not in st.session_state:
    st.session_state.capturing = False
if "thread" not in st.session_state:
    st.session_state.thread = None
if "stop_event" not in st.session_state:
    st.session_state.stop_event = threading.Event()


# --- Initialisation session_state ---
if "capturing" not in st.session_state:
    st.session_state.capturing = False
if "stop_event" not in st.session_state:
    st.session_state.stop_event = threading.Event()

# --- Bouton démarrer ---
if start_btn and not st.session_state.capturing:
    st.session_state.stop_event.clear()
    st.session_state.capturing = True
    st.session_state.thread = threading.Thread(
        target=sniff_thread,
        args=(iface, st.session_state.stop_event),
        daemon=True
    )
    st.session_state.thread.start()
    st.success(f"🛰️ Capture démarrée sur {iface}")

# --- Bouton arrêter ---
if stop_btn and st.session_state.capturing:
    st.session_state.stop_event.set()
    st.success("✅ Capture arrêtée")
#/////

def build_feature_row(fl: Flow) -> dict:
    stats = window_stats_for(fl, now_ms())
    feat = fl.to_features(stats)
    # Assurer que toutes les colonnes existent (même si 0)
    for c in FEATURE_COLUMNS:
        if c not in feat:
            feat[c] = 0
    return {c: feat[c] for c in FEATURE_COLUMNS}

def predict_df(df: pd.DataFrame):
    if model is None:
        # Mode démo : renvoie 0 pour normal
        preds = np.zeros((len(df),), dtype=int)
        proba = np.zeros((len(df), 2))
    return preds, proba

# Tableau temps réel
place_table = st.empty()
place_alert = st.empty()

def render_table():
    rows = []
    with lock:
        # ne pas saturer : max 200 flux en vue
        for key, fl in list(flows.items())[-200:]:
            row = build_feature_row(fl)
            rows.append(row)

    if not rows:
        return None, None, None

    df = pd.DataFrame(rows, columns=FEATURE_COLUMNS)
    preds, proba = predict_df(df)
    df_out = df.copy()
    df_out["proto"] = [fl.proto for key, fl in list(flows.items())[-200:]]
    df_out["prediction"] = preds
    if proba is not None and proba.shape[1] >= 2:
        df_out["p_attack"] = proba[:, 1]

    cols_to_show = ["proto", "service_http", "service_https", "service_dns", "service_ssh", "service_ftp", "service_smtp", "service_other", "prediction"]
    place_table.dataframe(df_out[cols_to_show + [c for c in df_out.columns if c not in cols_to_show]].tail(30), use_container_width=True)
    st.subheader("📊 Statistiques par service")
    
    services = ["service_http", "service_https", "service_dns", "service_ssh", "service_ftp", "service_smtp", "service_other"]
    service_counts = {s: int(df_out[s].sum()) for s in services}
    st.bar_chart(pd.Series(service_counts))

    # Alerte simple : si une probabilité d'attaque > 0.8
    if proba is not None and len(proba) > 0 and float(np.max(proba[:,1])) > 0.8:
        place_alert.error("⚠️ Intrusion probable détectée (p>0.8)")
    else:
        place_alert.info("Aucune alerte élevée pour le moment.")
    return df, preds, proba

# Boucle de rafraîchissement doux
# refresh_interval = 1.0
# while True:
#     df_cur, preds_cur, proba_cur = render_table()
#     time.sleep(refresh_interval)

if __name__ == "__main__" or True:
    df_cur, preds_cur, proba_cur = render_table()
    st.rerun()
    # Streamlit s'occupe de rafraîchir l'affichage sans rerun explicite

# === Affichage des logs ===
# if captured_data:
#     df_logs = pd.DataFrame(captured_data)
#     st.subheader("📋 Journaux du trafic")
#     st.dataframe(df_logs)

#     st.subheader("📈 Statistiques par protocole")
#     st.bar_chart(df_logs['protocol_type'].value_counts())

#     st.subheader("📊 Statistiques par service")
#     st.bar_chart(df_logs['service'].value_counts())

#     csv = df_logs.to_csv(index=False).encode("utf-8")
#     st.download_button("📥 Télécharger les logs", csv, "logs_intrusions.csv", "text/csv")
# else:
#     st.info("Aucune donnée capturée pour l’instant.")
