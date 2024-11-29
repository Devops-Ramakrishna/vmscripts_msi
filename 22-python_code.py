import pandas as pd

def process_text_to_excel(input_file, output_file):
    with open(input_file, 'r') as file:
        lines = file.readlines()

    data = []
    columns = []
    header_processed = False

    for line in lines:
        if line.startswith('+'):
            continue
        if '|' in line:
            cells = [cell.strip() for cell in line.split('|')[1:-1]]
            if not header_processed:
                columns = cells
                header_processed = True
            else:
                data.append(cells)

    # Adjust row lengths to match column count
    cleaned_data = []
    for row in data:
        while len(row) < len(columns):
            row.append('')  # Pad with empty strings
        cleaned_data.append(row[:len(columns)])  # Truncate if too long

    # Create DataFrame
    df = pd.DataFrame(cleaned_data, columns=columns)

    # Consolidate multi-line descriptions into one cell
    description_col = 'DESCRIPTION'  # Adjust this if the description column name is different
    if description_col in df.columns:
        df[description_col] = df[description_col].str.replace(r'\s+', ' ', regex=True)

    # Export to Excel
    df.to_excel(output_file, index=False)
    print(f"File has been saved to: {output_file}")


# Usage example:
input_file = "old.txt"  # Replace with the path to your text file
output_file = "old_vul.xlsx"  # Replace with the desired output path

process_text_to_excel(input_file, output_file)