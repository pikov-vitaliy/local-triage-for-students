# Ollama только для процессора: тот же выпуск, что ollama/ollama, без библиотек CUDA, MLX и Vulkan
# (официальный образ весит больше 9 ГБ, этот – около 200 МБ). Используется в образе ВМ, где видеокарты нет.
# Сборка: docker build -t local-triage-ollama-cpu:0.40.4 deploy/vm/ollama-cpu
ARG OLLAMA_VERSION=0.40.4
FROM ollama/ollama:${OLLAMA_VERSION} AS full
RUN rm -rf /usr/lib/ollama/cuda_v12 /usr/lib/ollama/cuda_v13 /usr/lib/ollama/mlx_cuda_v13 \
           /usr/lib/ollama/vulkan /usr/lib/ollama/include

FROM ubuntu:24.04
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends ca-certificates >/dev/null \
 && rm -rf /var/lib/apt/lists/*
COPY --from=full /usr/bin/ollama /usr/bin/ollama
COPY --from=full /usr/lib/ollama /usr/lib/ollama
ENV OLLAMA_HOST=0.0.0.0:11434 \
    OLLAMA_MODELS=/root/.ollama/models
EXPOSE 11434
ENTRYPOINT ["/bin/ollama"]
CMD ["serve"]
