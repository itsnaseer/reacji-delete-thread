from bolt_app import flask_app  # Import the Flask app from bolt_app

if __name__ == "__main__":
    flask_app.run(port=int(os.getenv("PORT", 3000)))