import os

def count_lines_in_file(file_path):
    """
    Menghitung jumlah baris dalam satu file dengan aman.
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f)
    except Exception as e:
        print(f"[ERROR] Gagal membaca {file_path}: {e}")
        return 0


def count_rust_lines(root_dir="crates"):
    total_lines = 0
    file_count = 0

    for root, dirs, files in os.walk(root_dir):
        for file in files:
            if file.endswith(".rs") or file.endswith(".rss"):
                file_path = os.path.join(root, file)
                lines = count_lines_in_file(file_path)

                total_lines += lines
                file_count += 1

    return total_lines, file_count


if __name__ == "__main__":
    root_folder = "crates"  # folder utama
    total_lines, total_files = count_rust_lines(root_folder)

    print("=== Rust Code Line Counter ===")
    print(f"Root folder : {root_folder}")
    print(f"Rust files  : {total_files}")
    print(f"Total lines : {total_lines}")
