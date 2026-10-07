# One image, two roles:
#   central server:  docker run ... systemlens central serve --host 0.0.0.0
#   agent:           docker run -v /var/run/docker.sock:/var/run/docker.sock ... systemlens start
# See docs/DEPLOYMENT.md for both.
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 \
    SYSTEMLENS_HOME=/data
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir "$(ls /tmp/*.whl)[groq,api,mcp]" && rm /tmp/*.whl \
    && useradd --uid 10001 --create-home --home-dir /home/systemlens systemlens \
    && mkdir -p /data && chown systemlens:systemlens /data
USER systemlens
VOLUME /data
EXPOSE 8500
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8500/health', timeout=2)" || exit 1
ENTRYPOINT ["systemlens"]
CMD ["central", "serve", "--host", "0.0.0.0"]
