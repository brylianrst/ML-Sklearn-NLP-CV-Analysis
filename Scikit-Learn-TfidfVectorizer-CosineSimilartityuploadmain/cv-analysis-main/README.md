Curl commands to run main_app.py (this is the benchmark code):
curl.exe -X POST http://127.0.0.1:5000/api/upload-cvs
.\check_task_status.ps1
curl.exe --location --request GET "http://127.0.0.1:5000/api/analyze-cvs/<task_id>"
curl.exe -X GET http://127.0.0.1:5000/api/export-csv/<task_id> --output results.csv