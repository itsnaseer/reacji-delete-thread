import os
import logging
from slack_bolt import App
from slack_bolt.oauth.oauth_settings import OAuthSettings
from slack_sdk.errors import SlackApiError
from slack_bolt.adapter.flask import SlackRequestHandler
from flask import Flask, request
from bolt_app import flask_app  # Import the Flask app from bolt_app

if __name__ == "__main__":
    flask_app.run(port=int(os.getenv("PORT", 3000)))