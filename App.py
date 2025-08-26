import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import datetime

#python -m streamlit run "D:\TFC\IDS concepting\program\App.py"

# Charger les données NSL-KDD
@st.cache_data
def load_data():
    #url = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt"
    url = "KDDTest+.txt"
    names = [
        "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
        "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
        "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
        "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
        "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
        "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
        "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
        "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
        "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty"
    ]
    return pd.read_csv(url, names=names)

data = load_data()

# ---- Interface principale ----

st.set_page_config(layout="wide")
st.title("🛡️ IDS - Détection d'intrusions sur réseau local")

st.markdown("📍 **Position recommandée** : placer cette application sur une machine **passerelle ou configurée sur un port SPAN** du routeur pour intercepter tout le trafic réseau local.")

# ---- Statistiques ----
st.subheader("📊 Vue générale")

col1, col2, col3 = st.columns(3)
col1.metric("Total connexions", len(data))
col2.metric("Trafic normal", (data['label'] == 'normal').sum())
col3.metric("Intrusions", (data['label'] != 'normal').sum())

# ---- Graphe Services/Protocoles ----
st.subheader("🔁 Services utilisés par Protocole")
fig1, ax1 = plt.subplots(figsize=(10, 4))
pivot = data.pivot_table(index="protocol_type", columns="service", aggfunc="size", fill_value=0)
sns.heatmap(pivot, cmap="YlGnBu", ax=ax1)
st.pyplot(fig1)

# ---- Journaux détaillés ----
st.subheader("📋 Journaux de trafic (extraits)")
now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
logs = data[["protocol_type", "service", "src_bytes", "dst_bytes", "label"]].copy()
logs["Utilisateur"] = "Client X"
logs["Port"] = 1024 + (logs.index % 3000)
logs["Horodatage"] = now
logs.rename(columns={
    "protocol_type": "Protocole",
    "service": "Service",
    "src_bytes": "Octets sortants",
    "dst_bytes": "Octets entrants",
    "label": "Type de trafic"
}, inplace=True)

st.dataframe(logs.head(25), use_container_width=True)

# ---- Exportation des logs ----
csv = logs.to_csv(index=False).encode("utf-8")
st.download_button("📥 Télécharger les logs", csv, "logs_reseau.csv", "text/csv")

# ---- Statistiques dynamiques ----
st.subheader("📈 Statistiques selon le type de trafic")

proto_stats = data.groupby("protocol_type")["label"].value_counts().unstack().fillna(0)
st.bar_chart(proto_stats)

service_stats = data["service"].value_counts().head(10)
st.subheader("🔝 Top 10 Services les plus fréquents")
st.bar_chart(service_stats)

st.markdown("---")
st.markdown("🧠 *Simulation basée sur NSL-KDD. Pour capture réelle, utiliser Scapy/Pyshark + extraction de caractéristiques.*")
