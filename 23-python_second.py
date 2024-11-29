import pandas as pd

# Load the Excel file
file_path = 'C:/Users/FWXT73/Desktop/JUNK/Anirudh/converted_data.xlsx' # Replace with your file path

# Check if the file exists before proceeding
try:
    data = pd.read_excel(file_path, sheet_name='Sheet1')
except Exception as e:
    print(f"Error loading file: {e}")
    exit()

# Step 1: Remove completely blank rows
cleaned_data = data.dropna(how='all')

# Step 2: Forward fill CVE values
cleaned_data.loc[:, 'CVE'] = cleaned_data['CVE'].ffill()

# Step 3: Merge fragmented descriptions using a loop
final_data = []
for cve, group in cleaned_data.groupby('CVE'):
    group = group.copy()  # Work with a copy to avoid unintended warnings
    merged_description = group['DESCRIPTION'].fillna('').str.cat(sep=' ')
    first_row = group.iloc[0].copy()  # Create a true copy of the first row
    first_row['DESCRIPTION'] = merged_description
    final_data.append(first_row)

# Convert the result back to a DataFrame
merged_data = pd.DataFrame(final_data)

# Save the cleaned data to an Excel file
merged_data.to_excel('cleaned_data.xlsx', index=False)

print("Data cleaned and saved successfully.")