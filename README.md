![logo](assets/logo.png)
{{ $values := (datasource "values") }}
# {{ $values.general.ctf.name }}
{{- range $values.general.ctf.urls }}
- {{ . }}
{{- end }}

## Description
*{{ $values.general.ctf.description }}*


# Results
**Username:** {{ .Env.CTF_USERNAME }}

**Team:** {{ .Env.CTF_TEAM }}


**Flags:** (0/X)

![ ](assets/scoreboard.png)
![ ](assets/team-score.png)


# Challenges
