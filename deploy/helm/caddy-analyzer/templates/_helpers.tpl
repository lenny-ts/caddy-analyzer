{{- define "caddy-analyzer.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "caddy-analyzer.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "caddy-analyzer.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "caddy-analyzer.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "caddy-analyzer.selectorLabels" -}}
app.kubernetes.io/name: {{ include "caddy-analyzer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
