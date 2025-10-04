bash:
	docker run --rm \
	-w /app \
	-v ./:/app \
	-p 8000:8000 \
	-it python:3.11 bash\