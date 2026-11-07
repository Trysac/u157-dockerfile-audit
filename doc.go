// Package dockerfileaudit provides Dockerfile parsing and security auditing.
//
// It inspects Dockerfiles against 9 focused security rules:
//   - DF001: Unpinned base image
//   - DF002: Missing or root USER in final stage
//   - DF003: Remote ADD without --checksum
//   - DF004: Local source ADD instead of COPY
//   - DF005: Sensitive default credentials in ENV or ARG
//   - DF006: Curl or wget piped to shell in RUN
//   - DF007: Usage of sudo in RUN
//   - DF008: Overly permissive chmod 777 or a+rwx
//   - DF009: SSH daemon port EXPOSE 22
package dockerfileaudit
