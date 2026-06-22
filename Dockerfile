FROM golang:latest AS nuclei-builder

RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

FROM python:3.12-slim

WORKDIR /app

COPY --from=nuclei-builder /go/bin/nuclei /usr/local/bin/nuclei

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p results

ENV PORT=10000

EXPOSE 10000

CMD gunicorn app:app --bind 0.0.0.0:$PORT --timeout 300
