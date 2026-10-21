/* UpdateKit.dll — self-update behind one clean C ABI.
 * All strings UTF-8, NUL-terminated. char* results are caller-owned:
 * free with uk_free_string(). On failure they return NULL / an error
 * code; see uk_last_error() and uk_last_error_code().
 *
 * Pipeline: uk_check_update() fetches a static JSON manifest and
 * reports whether a newer version exists; uk_download() streams the
 * package to disk, verifying its SHA-256 before succeeding (a bad
 * package is deleted, never left behind). Applying the staged
 * package is the app's job in v0.1. */
#ifndef UPDATEKIT_H
#define UPDATEKIT_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#if defined(_WIN32) && defined(UK_BUILD)
#define UK_API __declspec(dllexport)
#elif defined(_WIN32)
#define UK_API __declspec(dllimport)
#else
#define UK_API
#endif
#define UK_OK 0
#define UK_ERR_INVALID_ARG 1
#define UK_ERR_NOT_SUPPORTED 2
#define UK_ERR_NOT_FOUND 3
#define UK_ERR_ACCESS_DENIED 4
#define UK_ERR_PLATFORM 5
#define UK_ERR_INTERNAL 6
/* Extension beyond the shared 0-6 set (same pattern as ArchiveKit):
 * the bytes do not match the expected SHA-256. */
#define UK_ERR_CORRUPT 7

UK_API const char *uk_version(void);
UK_API int uk_version_major(void);
UK_API int uk_version_minor(void);
UK_API int uk_version_patch(void);
UK_API const char *uk_last_error(void);
UK_API int uk_last_error_code(void);
UK_API void uk_free_string(char *p);

/* Compare two version strings ("1.10.0" vs "1.9.9", optional
 * "-prerelease" suffixes). On UK_OK, *out_result is -1, 0 or 1. */
UK_API int uk_compare_versions(const char *a, const char *b, int *out_result);

/* Fetch + evaluate the manifest at manifest_url for current_version.
 * Returns caller-owned result JSON, or NULL on failure:
 * {"update_available":bool,"current_version":"...","latest_version":"...",
 *  "mandatory":bool,"package_url":"..."|null,"sha256":"..."|null,
 *  "size":N|null,"notes":"..."} */
UK_API char *uk_check_update(const char *current_version, const char *manifest_url);

/* Progress callback: called after each chunk with bytes downloaded
 * and the total (0 = unknown). Return 0 to continue, non-zero to
 * abort. May be NULL. */
typedef int (*uk_progress_fn)(void *ctx, uint64_t downloaded, uint64_t total);

/* Download url to dest_path, verifying expected_sha256 (64 hex chars)
 * when non-NULL. Returns UK_OK on success; partial/bad files are
 * removed on failure. */
UK_API int uk_download(const char *url, const char *dest_path,
                       const char *expected_sha256,
                       uk_progress_fn progress, void *ctx);

/* Like uk_download, but returns caller-owned result JSON
 * ({"path":"...","bytes":N,"sha256":"..."}) or NULL on failure. */
UK_API char *uk_download_json(const char *url, const char *dest_path,
                              const char *expected_sha256,
                              uk_progress_fn progress, void *ctx);

/* Verify an on-disk file against an expected SHA-256 hex digest.
 * UK_OK when it matches, UK_ERR_CORRUPT when it does not. */
UK_API int uk_verify_file(const char *path, const char *expected_sha256);

#ifdef __cplusplus
}
#endif
#endif
