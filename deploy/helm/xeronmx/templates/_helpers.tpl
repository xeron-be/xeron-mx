{{- define "xeronmx.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "xeronmx.fullname" -}}
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

{{- define "xeronmx.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "xeronmx.labels" -}}
helm.sh/chart: {{ include "xeronmx.chart" . }}
{{ include "xeronmx.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "xeronmx.selectorLabels" -}}
app.kubernetes.io/name: {{ include "xeronmx.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "xeronmx.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "xeronmx.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "xeronmx.headlessName" -}}
{{- printf "%s-headless" (include "xeronmx.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
The in-cluster address of one replica.

A StatefulSet gives every pod a name that survives rescheduling, so peer
addresses can be generated instead of configured. That is the whole reason this
chart uses a StatefulSet even at one replica.
*/}}
{{- define "xeronmx.podURL" -}}
{{- $full := include "xeronmx.fullname" .ctx -}}
{{- $headless := include "xeronmx.headlessName" .ctx -}}
{{- $port := int .ctx.Values.ui.containerPort -}}
{{- printf "http://%s-%d.%s.%s.svc.cluster.local:%d" $full (int .index) $headless .ctx.Release.Namespace $port -}}
{{- end -}}

{{- define "xeronmx.peerList" -}}
{{- $ctx := . -}}
{{- $peers := list -}}
{{- range $i := until (int .Values.replicaCount) -}}
{{- $peers = append $peers (include "xeronmx.podURL" (dict "ctx" $ctx "index" $i)) -}}
{{- end -}}
{{- join "," $peers -}}
{{- end -}}

{{- define "xeronmx.secretName" -}}
{{- if .Values.existingSecret -}}
{{- .Values.existingSecret -}}
{{- else -}}
{{- include "xeronmx.fullname" . -}}
{{- end -}}
{{- end -}}

{{/*
Whether the chart needs to create a Secret of its own. It does not when the
operator supplied one, and it does not when there is nothing secret to put in it.
*/}}
{{- define "xeronmx.createSecret" -}}
{{- if .Values.existingSecret -}}
false
{{- else if or .Values.cluster.secret .Values.oidc.clientSecret .Values.metrics.token .Values.alerts.email.password .Values.spam.password -}}
true
{{- else -}}
false
{{- end -}}
{{- end -}}
