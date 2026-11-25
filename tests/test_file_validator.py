import pytest
 
from src.file_validator import validate_file
 
 
def test_valid_csv_file(tmp_path):
    file = tmp_path / "logs.csv"
    file.write_text("test", encoding="utf-8")
 
    assert validate_file(file) == ".csv"
 
 
def test_valid_json_file(tmp_path):
    file = tmp_path / "logs.json"
    file.write_text("{}", encoding="utf-8")
 
    assert validate_file(file) == ".json"
 
 
def test_invalid_extension(tmp_path):
    file = tmp_path / "logs.exe"
    file.write_text("test", encoding="utf-8")
 
    with pytest.raises(
        ValueError,
        match="Unsupported file extension"
    ):
        validate_file(file)
 
 
def test_empty_file(tmp_path):
    file = tmp_path / "empty.csv"
    file.write_text("", encoding="utf-8")
 
    with pytest.raises(
        ValueError,
        match="The file is empty"
    ):
        validate_file(file)
 
 
def test_oversized_file(tmp_path):
    file = tmp_path / "large.csv"
 
    with open(file, "wb") as output:
        output.truncate(51 * 1024 * 1024)
        #output.truncate(11 * 1024 * 1024)
 
    #with pytest.raises(
        #ValueError,
        #match="10 MB"
    with pytest.raises(
        ValueError,
        match="50 MB"
    ):
        validate_file(file)

 
