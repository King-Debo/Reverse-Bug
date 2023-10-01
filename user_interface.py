# Import the Flask module and create an app instance
from flask import Flask, render_template, request, redirect, url_for
app = Flask(__name__)

# Import the database module and create a database instance
from database import Database
db = Database()

# Import the malware detection module and create a malware detection instance
from malware_detection import MalwareDetection
md = MalwareDetection()

# Import the static analysis module and create a static analysis instance
from static_analysis import StaticAnalysis
sa = StaticAnalysis()

# Import the dynamic analysis module and create a dynamic analysis instance
from dynamic_analysis import DynamicAnalysis
da = DynamicAnalysis()

# Import the report generation module and create a report generation instance
from report_generation import ReportGeneration
rg = ReportGeneration()

# Define the route for the home page
@app.route("/")
def home():
    # Render the home.html template, which shows the welcome message and the upload form
    return render_template("home.html")

# Define the route for the upload page
@app.route("/upload", methods=["POST"])
def upload():
    # Get the file object from the request
    file = request.files["file"]
    # Check if the file is valid
    if file and file.filename.endswith(".exe"):
        # Save the file to the database
        db.save_file(file)
        # Redirect to the analysis page, passing the file id as a parameter
        return redirect(url_for("analysis", file_id=file.id))
    else:
        # Render the error.html template, which shows an error message
        return render_template("error.html", message="Invalid file. Please upload a valid executable file.")

# Define the route for the analysis page
@app.route("/analysis/<file_id>")
def analysis(file_id):
    # Get the file object from the database using the file id
    file = db.get_file(file_id)
    # Check if the file exists
    if file:
        # Perform the malware detection on the file
        md_result = md.detect(file)
        # Perform the static analysis on the file
        sa_result = sa.analyze(file)
        # Perform the dynamic analysis on the file
        da_result = da.analyze(file)
        # Perform the report generation on the file
        rg_result = rg.generate(file, md_result, sa_result, da_result)
        # Render the analysis.html template, which shows the analysis results
        return render_template("analysis.html", file=file, md_result=md_result, sa_result=sa_result, da_result=da_result, rg_result=rg_result)
    else:
        # Render the error.html template, which shows an error message
        return render_template("error.html", message="File not found. Please upload a valid file.")

# Run the app
if __name__ == "__main__":
    app.run(debug=True)
