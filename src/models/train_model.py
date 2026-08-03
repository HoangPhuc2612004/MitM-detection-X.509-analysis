import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score, classification_report,
    confusion_matrix, precision_score, recall_score, f1_score
)
import joblib
import warnings
warnings.filterwarnings('ignore')

print("=" * 60)
print("  MITM DETECTION - TRAINING PIPELINE (FIXED)")
print("=" * 60)


# ══════════════════════════════════════════════════════════
# 1. ĐỌC DỮ LIỆU
# ══════════════════════════════════════════════════════════
print("\n[1] Đọc dữ liệu...")
df = pd.read_csv("dataset_chinh.csv")
print(f"    Tổng số mẫu : {len(df)}")
print(f"    Số cột      : {len(df.columns)}")
print(f"    Phân bố nhãn:\n{df['label'].value_counts()}")


# ══════════════════════════════════════════════════════════
# 2. KIỂM TRA FEATURE LEAKAGE TRƯỚC KHI TRAIN
# ══════════════════════════════════════════════════════════
print("\n[2] Kiểm tra Feature Leakage...")

leakage_report = {}
for col in df.columns:
    if col in ['label', 'Domain', 'Fingerprint']:
        continue
    try:
        if df[col].dtype == object:
            corr = df.groupby(col)['label'].mean().std()
            leakage_report[col] = round(corr, 4)
        else:
            corr = abs(df[col].corr(df['label']))
            leakage_report[col] = round(corr, 4)
    except Exception:
        pass

print("    Tương quan với label (>0.8 = nguy cơ leakage):")
for feat, val in sorted(leakage_report.items(), key=lambda x: -x[1]):
    flag = "   LEAKAGE RISK" if val > 0.8 else ""
    print(f"    {feat:<30}: {val:.4f}{flag}")

if 'Issuer' in df.columns and 'Is_Trusted_CA' in df.columns:
    overlap = df.groupby('Issuer')['Is_Trusted_CA'].nunique()
    if (overlap == 1).all():
        print("\n      Is_Trusted_CA được xác định 100% bởi Issuer")
        print("       → Giữ lại Is_Trusted_CA nhưng BỎ khỏi feature ML")
        print("       → Chỉ dùng để hiển thị trong NIDS")


# ══════════════════════════════════════════════════════════
# 3. FEATURES & ENCODING
# ══════════════════════════════════════════════════════════
print("\n[3] Chuẩn bị features (đã loại feature leakage)...")

CATEGORICAL_COLS = ['Issuer', 'Signature_Algorithm', 'Public_Key_Type', 'Version']
NUMERICAL_COLS   = ['Validity_Days', 'Key_Length', 'Has_SAN']

le_dict = {}
df_enc  = df.copy()
for col in CATEGORICAL_COLS:
    le = LabelEncoder()
    df_enc[col + '_enc'] = le.fit_transform(df_enc[col].astype(str))
    le_dict[col] = le

FEATURE_COLS = [c + '_enc' for c in CATEGORICAL_COLS] + NUMERICAL_COLS
X = df_enc[FEATURE_COLS]
y = df_enc['label']
print(f"    Features sử dụng ({len(FEATURE_COLS)}): {FEATURE_COLS}")


# ══════════════════════════════════════════════════════════
# 4. TRAIN/TEST SPLIT
# ══════════════════════════════════════════════════════════
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"\n[4] Train: {len(X_train)} | Test: {len(X_test)}")


# ══════════════════════════════════════════════════════════
# 5. TRAIN MODEL 
# ══════════════════════════════════════════════════════════
print("\n[5] Huấn luyện Random Forest (chống overfitting)...")
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=12,           
    min_samples_split=10,    
    min_samples_leaf=5,      
    max_features='sqrt',   
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)


# ══════════════════════════════════════════════════════════
# 6. ĐÁNH GIÁ — SO SÁNH TRAIN vs TEST (phát hiện overfit)
# ══════════════════════════════════════════════════════════
y_pred_test  = model.predict(X_test)
y_pred_train = model.predict(X_train)

acc_train = accuracy_score(y_train, y_pred_train) * 100
acc_test  = accuracy_score(y_test,  y_pred_test)  * 100
prec      = precision_score(y_test, y_pred_test)  * 100
rec       = recall_score(y_test,    y_pred_test)  * 100
f1        = f1_score(y_test,        y_pred_test)  * 100

cv        = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_scores = cross_val_score(model, X, y, cv=cv, scoring='f1')

print("\n" + "=" * 60)
print("  KẾT QUẢ ĐÁNH GIÁ")
print("=" * 60)
print(f"  Train Accuracy  : {acc_train:.2f}%")
print(f"  Test  Accuracy  : {acc_test:.2f}%")
gap = acc_train - acc_test
if gap > 5:
    print(f"  Gap Train-Test  : {gap:.2f}%    VẪN CÒN OVERFIT")
else:
    print(f"  Gap Train-Test  : {gap:.2f}%   Chấp nhận được")

print(f"\n  Precision       : {prec:.2f}%")
print(f"  Recall          : {rec:.2f}%")
print(f"  F1-Score        : {f1:.2f}%")
print(f"  CV F1 (5-fold)  : {cv_scores.mean()*100:.2f}% ± {cv_scores.std()*100:.2f}%")

if acc_test >= 99.5:
    print("\n    Test accuracy vẫn 100% — kiểm tra lại dataset:")
    print("     • Dataset có thể quá đơn giản / pattern quá rõ")
    print("     • Thử thêm noise hoặc dùng dataset thực tế hơn")

print("\n[+] Classification Report:")
print(classification_report(y_test, y_pred_test,
      target_names=["CLEAN (0)", "MITM (1)"], digits=4))

feat_imp = pd.Series(model.feature_importances_,
                     index=FEATURE_COLS).sort_values(ascending=False)
print("[+] Feature Importance:")
for name, imp in feat_imp.items():
    bar = "█" * int(imp * 50)
    print(f"  {name:<25}: {imp:.4f} {bar}")


# ══════════════════════════════════════════════════════════
# 7. LƯU MODEL
# ══════════════════════════════════════════════════════════
joblib.dump(model,        "mitm_model.pkl")
joblib.dump(le_dict,      "label_encoders.pkl")
joblib.dump(FEATURE_COLS, "model_features.pkl")
print("\n[OK] Đã lưu: mitm_model.pkl | label_encoders.pkl | model_features.pkl")


# ══════════════════════════════════════════════════════════
# 8. VẼ BIỂU ĐỒ
# ══════════════════════════════════════════════════════════
print("\n[7] Xuất training_report.png...")

C = {
    'bg'    : '#0F1117', 'card'  : '#1A1D2E',
    'clean' : '#4ADE80', 'mitm'  : '#F87171',
    'blue'  : '#60A5FA', 'purple': '#A78BFA',
    'yellow': '#FBBF24', 'teal'  : '#2DD4BF',
    'text'  : '#E2E8F0', 'sub'   : '#64748B',
    'border': '#2D3748',
}
plt.rcParams.update({
    'text.color': C['text'], 'axes.labelcolor': C['sub'],
    'xtick.color': C['sub'], 'ytick.color': C['sub'],
    'axes.facecolor': C['card'], 'figure.facecolor': C['bg'],
    'axes.spines.top': False, 'axes.spines.right': False,
    'axes.spines.left': False, 'axes.spines.bottom': False,
    'axes.grid': True, 'grid.color': C['border'],
    'grid.linewidth': 0.5, 'grid.alpha': 0.5,
})

fig = plt.figure(figsize=(20, 16))
fig.patch.set_facecolor(C['bg'])
fig.text(0.5, 0.978, 'MITM Detection — Training Report',
         ha='center', fontsize=20, fontweight='bold', color=C['text'])
fig.text(0.5, 0.960,
         f'Random Forest  ·  {len(df)} samples  ·  '
         f'{len(FEATURE_COLS)} features  ·  Test Acc {acc_test:.1f}%  ·  '
         f'Train-Test Gap {gap:.1f}%',
         ha='center', fontsize=12, color=C['sub'])

# [A] Pie - phân bố nhãn
ax1 = fig.add_axes([0.03, 0.67, 0.20, 0.27])
ax1.set_facecolor(C['card'])
lc = df['label'].value_counts().sort_index()
wedges, _, autotexts = ax1.pie(
    lc, labels=['CLEAN', 'MITM'],
    colors=[C['clean'], C['mitm']],
    autopct='%1.1f%%', startangle=90,
    wedgeprops=dict(edgecolor=C['bg'], linewidth=3),
    textprops=dict(color=C['text'], fontsize=11))
for at in autotexts:
    at.set_fontsize(12); at.set_fontweight('bold')
ax1.set_title('Phân bố nhãn', color=C['text'],
              fontsize=13, pad=12, fontweight='bold')

# [B] Metrics bar
ax2 = fig.add_axes([0.27, 0.67, 0.35, 0.27])
ax2.set_facecolor(C['card'])
m_names  = ['Train Acc', 'Test Acc', 'Precision', 'Recall', 'F1-Score']
m_values = [acc_train, acc_test, prec, rec, f1]
m_colors = [C['purple'], C['blue'], C['purple'], C['teal'], C['yellow']]
bars = ax2.barh(m_names, m_values, color=m_colors,
                height=0.55, edgecolor=C['bg'], linewidth=2)
ax2.set_xlim(0, 120)
ax2.axvline(100, color=C['border'], linestyle='--', linewidth=1.5, alpha=0.8)
for bar, val in zip(bars, m_values):
    ax2.text(val + 1, bar.get_y() + bar.get_height()/2,
             f'{val:.2f}%', va='center', fontsize=11,
             fontweight='bold', color=C['text'])
ax2.set_xlabel('Score (%)')
ax2.set_title('Metrics (Train vs Test)', color=C['text'],
              fontsize=13, pad=12, fontweight='bold')

# [C] Confusion Matrix
ax3 = fig.add_axes([0.67, 0.65, 0.30, 0.30])
ax3.set_facecolor(C['card'])
cm = confusion_matrix(y_test, y_pred_test)
ax3.imshow(cm, cmap='RdYlGn', vmin=0, vmax=cm.max())
ax3.set_xticks([0, 1]); ax3.set_yticks([0, 1])
ax3.set_xticklabels(['CLEAN', 'MITM'], color=C['text'], fontsize=11)
ax3.set_yticklabels(['CLEAN', 'MITM'], color=C['text'], fontsize=11)
ax3.set_xlabel('Predicted', color=C['sub'])
ax3.set_ylabel('Actual', color=C['sub'])
ax3.set_title('Confusion Matrix', color=C['text'],
              fontsize=13, pad=12, fontweight='bold')
lbs = [['TN', 'FP'], ['FN', 'TP']]
for i in range(2):
    for j in range(2):
        ax3.text(j, i, f'{lbs[i][j]}\n{cm[i,j]}',
                 ha='center', va='center', fontsize=14,
                 fontweight='bold', color=C['bg'])

# [D] Feature Importance
ax4 = fig.add_axes([0.03, 0.36, 0.55, 0.26])
ax4.set_facecolor(C['card'])
n  = len(feat_imp)
fi = feat_imp.head(n)
fi_c = [C['mitm'] if i == 0 else C['blue'] if i == 1
        else C['purple'] for i in range(n)]
b2 = ax4.barh(range(n), fi.values[::-1], color=fi_c[::-1],
              height=0.6, edgecolor=C['bg'], linewidth=1.5)
ax4.set_yticks(range(n))
lfi = [x.replace('_enc','').replace('_',' ').title()
       for x in fi.index[::-1]]
ax4.set_yticklabels(lfi, color=C['text'], fontsize=10)
for bar, val in zip(b2, fi.values[::-1]):
    ax4.text(val + 0.002, bar.get_y() + bar.get_height()/2,
             f'{val:.4f}', va='center', fontsize=9, color=C['sub'])
ax4.set_xlabel('Importance Score')
ax4.set_title('Feature Importance ',
              color=C['text'], fontsize=13, pad=12, fontweight='bold')

# [E] Validity Days Distribution
ax5 = fig.add_axes([0.63, 0.36, 0.35, 0.26])
ax5.set_facecolor(C['card'])
cv_d = df[df['label'] == 0]['Validity_Days']
mv_d = df[df['label'] == 1]['Validity_Days']
ax5.hist(cv_d, bins=25, alpha=0.75, color=C['clean'],
         label='CLEAN', edgecolor=C['bg'])
ax5.hist(mv_d, bins=25, alpha=0.75, color=C['mitm'],
         label='MITM',  edgecolor=C['bg'])
ax5.axvline(cv_d.mean(), color=C['clean'], linestyle='--',
            linewidth=1.5, alpha=0.8)
ax5.axvline(mv_d.mean(), color=C['mitm'],  linestyle='--',
            linewidth=1.5, alpha=0.8)
ax5.set_xlabel('Validity Days')
ax5.set_ylabel('Count')
ax5.set_title('Phân bố Validity Days', color=C['text'],
              fontsize=13, pad=12, fontweight='bold')
ax5.legend(facecolor=C['card'], edgecolor='none',
           labelcolor=C['text'], fontsize=10)

# [F] Top Issuers
ax6 = fig.add_axes([0.03, 0.05, 0.55, 0.26])
ax6.set_facecolor(C['card'])
ig = df.groupby(['Issuer', 'label']).size().unstack(fill_value=0)
ig['total'] = ig.sum(axis=1)
ti = ig.nlargest(10, 'total')
x  = np.arange(len(ti))
w  = 0.38
if 0 in ti.columns:
    ax6.bar(x - w/2, ti[0], w, label='CLEAN',
            color=C['clean'], edgecolor=C['bg'], linewidth=1.5)
if 1 in ti.columns:
    ax6.bar(x + w/2, ti[1], w, label='MITM',
            color=C['mitm'],  edgecolor=C['bg'], linewidth=1.5)
ax6.set_xticks(x)
ax6.set_xticklabels(
    [s[:16] + '..' if len(s) > 16 else s for s in ti.index],
    rotation=30, ha='right', color=C['text'], fontsize=9)
ax6.set_ylabel('Count')
ax6.set_title('Top 10 Issuer theo nhãn', color=C['text'],
              fontsize=13, pad=12, fontweight='bold')
ax6.legend(facecolor=C['card'], edgecolor='none',
           labelcolor=C['text'], fontsize=10)

# [G] Cross-Validation
ax7 = fig.add_axes([0.63, 0.05, 0.35, 0.26])
ax7.set_facecolor(C['card'])
ax7.bar(range(1, 6), cv_scores * 100, color=C['blue'],
        edgecolor=C['bg'], linewidth=2, width=0.6)
mean_cv = cv_scores.mean() * 100
ax7.axhline(mean_cv, color=C['yellow'], linestyle='--',
            linewidth=2, label=f'Mean: {mean_cv:.2f}%')
ax7.fill_between(
    np.linspace(0.7, 5.3, 100),
    mean_cv - cv_scores.std() * 100,
    mean_cv + cv_scores.std() * 100,
    alpha=0.15, color=C['yellow'])
for i, v in enumerate(cv_scores):
    ax7.text(i + 1, v * 100 + 0.8, f'{v*100:.1f}%',
             ha='center', fontsize=10, fontweight='bold', color=C['text'])
ax7.set_xlabel('Fold')
ax7.set_ylabel('F1 Score (%)')
ax7.set_ylim(0, 115)
ax7.set_xticks(range(1, 6))
ax7.set_title('Cross-Validation F1 (5-Fold)', color=C['text'],
              fontsize=13, pad=12, fontweight='bold')
ax7.legend(facecolor=C['card'], edgecolor='none',
           labelcolor=C['text'], fontsize=10)

plt.savefig("training_report.png", dpi=150, bbox_inches='tight',
            facecolor=C['bg'], edgecolor='none')
print("[OK] Đã xuất: training_report.png")
print("\n" + "=" * 60)
print("  HOÀN THÀNH!")
print("=" * 60)