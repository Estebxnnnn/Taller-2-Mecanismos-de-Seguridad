"""Caso 4 – Detección de anomalías con IA/ML en tráfico TCP/IP (conjunto sintético, características agregadas por minuto).
Reproducible: semilla fija. Partición TEMPORAL: días 1-5 entrenamiento, días 6-7 evaluación (sin barajar → sin fuga).
Compara: (a) línea base estadística estacional (z robusto de conexiones/min por hora del día)
         (b) IsolationForest multivariable (scikit-learn).
"""
import numpy as np, pandas as pd, json, sklearn
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score, average_precision_score, precision_recall_curve
from lib import *
style()
rng = np.random.default_rng(4)
idx = pd.date_range("2026-10-29 00:00", periods=7*1440, freq="min", tz="America/Bogota")
h = idx.hour + idx.minute/60
dow = idx.dayofweek
diurnal = np.where((h >= 7) & (h < 19), 1 + 2.2*np.sin(np.pi*(h-7)/12), 0.25)
diurnal = np.where(dow >= 5, diurnal*0.45, diurnal)  # fin de semana
conn = rng.poisson(18 + 55*diurnal)
df = pd.DataFrame({
    "conexiones_min": conn,
    "bytes_por_flujo": rng.lognormal(np.log(15000), 0.35, len(idx)),
    "duracion_media_s": rng.gamma(4, 0.6, len(idx)),
    "ratio_syn_sin_ack": np.clip(rng.normal(0.02, 0.01, len(idx)), 0, 1),
    "ratio_rst": np.clip(rng.normal(0.012, 0.006, len(idx)), 0, 1),
    "ratio_pet_resp": np.clip(rng.lognormal(np.log(0.08), 0.25, len(idx)), 0, None),
    "puertos_dst_unicos": rng.poisson(4, len(idx)) + 1,
    "long_media_qname": rng.normal(16, 2.2, len(idx)),
}, index=idx)
df["etiqueta"] = 0; df["escenario"] = "normal"

def inject(start, minutes, name, **chg):
    sl = slice(pd.Timestamp(start, tz="America/Bogota"), pd.Timestamp(start, tz="America/Bogota") + pd.Timedelta(minutes=minutes-1))
    for k, f in chg.items():
        df.loc[sl, k] = f(df.loc[sl, k])
    if name != "carga_legitima":
        df.loc[sl, "etiqueta"] = 1
    df.loc[sl, "escenario"] = name

# pocas anomalías NO etiquetadas también en entrenamiento (realismo: los datos "normales" nunca son 100 % limpios)
inject("2026-10-30 15:10", 6, "ruido_entrenamiento", conexiones_min=lambda s: s*4, ratio_syn_sin_ack=lambda s: s+0.5)
inject("2026-11-01 03:00", 15, "ruido_entrenamiento", puertos_dst_unicos=lambda s: s+120)
df.loc[df.escenario == "ruido_entrenamiento", "etiqueta"] = 0  # no se usan etiquetas para entrenar

# anomalías de evaluación (días 6 y 7: 3 y 4 de noviembre)
inject("2026-11-03 10:20", 10, "syn_flood", conexiones_min=lambda s: s*6, ratio_syn_sin_ack=lambda s: s+0.85, duracion_media_s=lambda s: s*0.2)
inject("2026-11-03 14:05", 5, "escaneo_puertos", puertos_dst_unicos=lambda s: s+300, ratio_rst=lambda s: s+0.6)
inject("2026-11-03 21:30", 30, "tunel_dns", long_media_qname=lambda s: s+95, ratio_pet_resp=lambda s: s*1.8)
inject("2026-11-04 09:40", 20, "exfiltracion_http", ratio_pet_resp=lambda s: s*45, bytes_por_flujo=lambda s: s*90)
inject("2026-11-04 02:00", 60, "escaneo_lento", puertos_dst_unicos=lambda s: s+9)
inject("2026-11-04 16:30", 8, "rst_inyectados", ratio_rst=lambda s: s+0.18)
inject("2026-11-04 13:00", 120, "carga_legitima", conexiones_min=lambda s: s*3)  # cambio legítimo (jornada de inscripciones)

FEATS = ["conexiones_min", "bytes_por_flujo", "duracion_media_s", "ratio_syn_sin_ack", "ratio_rst", "ratio_pet_resp", "puertos_dst_unicos", "long_media_qname"]
df.to_csv(f"{EVID}/C4_dataset_agregado_por_minuto.csv", index_label="minuto")
train = df[df.index < pd.Timestamp("2026-11-03", tz="America/Bogota")]
test = df[df.index >= pd.Timestamp("2026-11-03", tz="America/Bogota")]

# ---------- (a) línea base estadística estacional: mediana y MAD por hora del día (entrenamiento)
g = train.groupby(train.index.hour)["conexiones_min"]
med, mad = g.median(), g.apply(lambda s: np.median(np.abs(s - s.median())) * 1.4826)
z_base = np.abs((test["conexiones_min"] - test.index.hour.map(med).values) / test.index.hour.map(mad).values)
pred_base = (z_base > 3.5).astype(int)

# ---------- (b) IsolationForest multivariable
def prep(X):
    X = X[FEATS].copy()
    for c in ["conexiones_min", "bytes_por_flujo", "ratio_pet_resp", "puertos_dst_unicos"]:
        X[c] = np.log1p(X[c])
    return X
Xtr, Xte = prep(train), prep(test)
mu, sd = Xtr.mean(), Xtr.std()
Xtr_s, Xte_s = (Xtr - mu) / sd, (Xte - mu) / sd
iforest = IsolationForest(n_estimators=300, max_samples=512, contamination="auto", random_state=7).fit(Xtr_s)
s_tr = -iforest.score_samples(Xtr_s); s_te = -iforest.score_samples(Xte_s)
thr = float(np.percentile(s_tr, 99.5))
pred_if = (s_te > thr).astype(int)
# persistencia: alerta solo si 2 de 3 minutos consecutivos superan el umbral (reduce falsos positivos aislados)
pred_if_p = (pd.Series(pred_if, index=test.index).rolling(3, center=True, min_periods=1).sum() >= 2).astype(int).values

y = test["etiqueta"].values
def metr(pred, score):
    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
    return dict(TP=int(tp), FP=int(fp), FN=int(fn), TN=int(tn), precision=round(precision_score(y, pred), 3), recall=round(recall_score(y, pred), 3),
                F1=round(f1_score(y, pred), 3), FPR=round(fp/(fp+tn), 4), exactitud=round((tp+tn)/len(y), 4), PR_AUC=round(average_precision_score(y, score), 3))
res = {"base_estadistica_z>3.5": metr(pred_base, z_base.values), "isolation_forest": metr(pred_if, s_te), "isolation_forest_persistencia_2de3": metr(pred_if_p, s_te),
       "umbral_iforest_p99.5_entrenamiento": round(thr, 4), "minutos_eval": int(len(y)), "minutos_anomalos": int(y.sum()), "prevalencia_pct": round(100*y.mean(), 2),
       "sklearn": sklearn.__version__, "clasificador_trivial_todo_normal_exactitud": round(1 - y.mean(), 4)}
# detección por escenario
det = {}
for sc in test.escenario.unique():
    m = (test.escenario == sc).values
    det[sc] = dict(minutos=int(m.sum()), base=round(float(pred_base[m].mean()), 2), iforest=round(float(pred_if_p[m].mean()), 2))
res["deteccion_por_escenario"] = det
json.dump(res, open(f"{WORK}/C4_metricas.json", "w"), indent=1, ensure_ascii=False)
print(json.dumps(res, indent=1, ensure_ascii=False))

# ---------- explicación de una alerta (z por atributo respecto al entrenamiento)
t_alert = pd.Timestamp("2026-11-04 09:45", tz="America/Bogota")
expl = ((Xte_s.loc[t_alert]).round(2)).sort_values(key=np.abs, ascending=False)
json.dump({"minuto": str(t_alert), "score": round(float(s_te[test.index.get_loc(t_alert)]), 4), "umbral": round(thr, 4), "z_por_atributo": expl.to_dict()},
          open(f"{WORK}/C4_explicacion_alerta.json", "w"), indent=1, ensure_ascii=False)

# ---------- figuras
fig, ax = plt.subplots(3, 1, figsize=(12, 8), sharex=True, gridspec_kw={"height_ratios": [1.2, 1.2, 0.6]})
ax[0].plot(test.index, test["conexiones_min"], lw=.6, color="#566573"); ax[0].set_ylabel("conexiones/min")
ax[0].set_title("Caso 4 · Evaluación (3–4 nov 2026): tráfico, puntuación de anomalía y etiquetas")
ax[1].plot(test.index, s_te, lw=.6, color="#2471a3", label="score IsolationForest"); ax[1].axhline(thr, color="#c0392b", ls="--", label=f"umbral p99,5 entren. = {thr:.3f}")
ax[1].set_ylabel("score de anomalía"); ax[1].legend(fontsize=8, loc="upper left")
cols = {"syn_flood": "#c0392b", "escaneo_puertos": "#8e44ad", "tunel_dns": "#d35400", "exfiltracion_http": "#1abc9c", "escaneo_lento": "#7f8c8d", "rst_inyectados": "#2c3e50", "carga_legitima": "#f1c40f"}
for sc, c in cols.items():
    m = test.escenario == sc
    if m.any():
        t0, t1 = test.index[m][0], test.index[m][-1]
        for a in ax[:2]: a.axvspan(t0, t1, color=c, alpha=.25)
        ax[2].barh(0, (t1 - t0).total_seconds()/86400 + 1/1440, left=t0, color=c, label=sc.replace("_", " "))
ax[2].set_yticks([]); ax[2].legend(ncol=4, fontsize=8, loc="upper center", bbox_to_anchor=(0.5, -0.35)); ax[2].set_ylabel("escenario")
import matplotlib.dates as mdates
ax[2].xaxis.set_major_formatter(mdates.DateFormatter("%d-%b %H:%M", tz=test.index.tz))
save_fig(fig, "c4_fig1_scores_temporal.png")

fig, axs = plt.subplots(1, 3, figsize=(13, 3.9))
for a, (name, pred) in zip(axs, [("Línea base z>3,5", pred_base), ("IsolationForest", pred_if), ("IForest + persistencia 2/3", pred_if_p)]):
    cm = confusion_matrix(y, pred)
    a.imshow(cm, cmap="Blues"); a.grid(False)
    for i in range(2):
        for j in range(2):
            a.text(j, i, f"{cm[i,j]}", ha="center", va="center", fontsize=13, weight="bold", color="white" if cm[i, j] > cm.max()/2 else "black")
    a.set_xticks([0, 1]); a.set_yticks([0, 1]); a.set_xticklabels(["pred. normal", "pred. anómalo"]); a.set_yticklabels(["real normal", "real anómalo"])
    a.set_title(name)
fig.suptitle("Caso 4 · Matrices de confusión (2 880 minutos de evaluación; 133 anómalos)", weight="bold", y=1.04)
fig.subplots_adjust(wspace=0.55)
save_fig(fig, "c4_fig2_matrices_confusion.png")

fig, a = plt.subplots(figsize=(6.5, 4.6))
for name, sc, c in [("Línea base (|z| conexiones)", z_base.values, "#7f8c8d"), ("IsolationForest", s_te, "#2471a3")]:
    p, r, _ = precision_recall_curve(y, sc); a.plot(r, p, color=c, label=f"{name} · PR-AUC={average_precision_score(y, sc):.3f}")
a.axhline(y.mean(), ls=":", color="#c0392b", label=f"azar (prevalencia {100*y.mean():.1f} %)")
a.set_xlabel("Recall (sensibilidad)"); a.set_ylabel("Precisión"); a.set_title("Caso 4 · Curvas precisión–recall"); a.legend(fontsize=8)
save_fig(fig, "c4_fig3_curva_pr.png")

fig, a = plt.subplots(figsize=(7.5, 3.8))
e = expl.iloc[::-1]
a.barh(e.index, e.values, color=["#c0392b" if abs(v) > 3 else "#95a5a6" for v in e.values])
a.axvline(3, ls="--", color="#555", lw=.8); a.axvline(-3, ls="--", color="#555", lw=.8)
a.set_xlabel("desviación respecto a la línea base de entrenamiento (z, escala log en volúmenes)")
a.set_title("Caso 4 · Explicación de la alerta 04-nov 09:45 (exfiltración HTTP simulada)")
save_fig(fig, "c4_fig4_explicacion_alerta.png")
