{{/*
Chart name / fullname helpers.
*/}}
{{- define "circulusd.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "circulusd.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "circulusd.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "circulusd.labels" -}}
helm.sh/chart: {{ include "circulusd.chart" . }}
{{ include "circulusd.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: circulusd
circulusd.dev/profile: {{ .Values.profile | quote }}
circulusd.dev/production-eligible: "false"
{{- end -}}

{{- define "circulusd.selectorLabels" -}}
app.kubernetes.io/name: {{ include "circulusd.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "circulusd.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "circulusd.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "circulusd.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{/*
Validate the chosen profile early so a typo fails render instead of producing
an empty command.
*/}}
{{- define "circulusd.validateProfile" -}}
{{- $p := .Values.profile -}}
{{- if not (or (eq $p "development-reference") (eq $p "production-diagnostic")) -}}
{{- fail (printf "circulusd: profile must be development-reference or production-diagnostic, got %q" $p) -}}
{{- end -}}
{{- end -}}
