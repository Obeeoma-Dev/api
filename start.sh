#!/usr/bin/env bash

# Start Gunicorn
gunicorn api.wsgi:application --bind 0.0.0.0:$PORT
