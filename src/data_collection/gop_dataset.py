import pandas as pd

df_sach = pd.read_csv("dataset.csv")
df_gia = pd.read_csv("dataset_gia_k1.csv")

# Gán nhãn tạm thời để theo dõi nguồn gốc dữ liệu trong quá trình kiểm tra
df_sach["source"] = "clean"
df_gia["source"] = "mitm"

# Kiểm chứng toàn vẹn cấu trúc đảm bảo hai tập dữ liệu đồng nhất
assert list(df_sach.columns) == list(df_gia.columns), "Lỗi: Cấu trúc cột của hai tệp không khớp nhau!"

# Hợp nhất dữ liệu
df_total = pd.concat([df_sach, df_gia], ignore_index=True)

# Khử nhiễu có chọn lọc: Chỉ drop những dòng bị khuyết các cột sống còn
df_total = df_total.dropna(subset=["Fingerprint", "Issuer", "Validity_Days"])

# Điền khuyết (FillNaN): Đắp giá trị mặc định cho các cột phụ bị thiếu để cứu lại luồng dữ liệu
df_total = df_total.fillna({
    "Signature_Algorithm": "Unknown",
    "Key_Length": 0,
    "Public_Key_Type": "Unknown",
    "Has_SAN": 0,
    "Version": "Unknown"
})

# Trích lọc: Loại bỏ chứng chỉ trùng lặp dựa trên mã băm duy nhất để đảm bảo chất lượng
df_total = df_total.drop_duplicates(subset=["Fingerprint"])

# Xáo trộn ngẫu nhiên để tránh tình trạng thuật toán học ghi nhớ theo thứ tự
df_final = df_total.sample(frac=1, random_state=42).reset_index(drop=True)

# Thống kê phân phối lớp nhãn
print("Thống kê số lượng mẫu sau khi hợp nhất và làm sạch:")
print(df_final["label"].value_counts())

# Xóa bỏ trường dữ liệu theo dõi để ngăn chặn triệt để lỗi rò rỉ dữ liệu (Data Leakage)
df_final = df_final.drop(columns=["source"])

# Kết xuất tập dữ liệu hoàn chỉnh
df_final.to_csv("dataset_chinh.csv", index=False)
print("\n[OK] Đã xuất tệp dataset.csv thành công!")
