#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Controls the amount of fault tolerance that the QR code should accept. Require the feature
 * flag `with-qrcode`.
 */
typedef enum ErrorCorrectionLevel {
  /**
   * 7% of data bytes can be restored.
   */
  Low,
  /**
   * 15% of data bytes can be restored.
   */
  Medium,
  /**
   * 25% of data bytes can be restored.
   */
  Quartile,
  /**
   * 30% of data bytes can be restored.
   */
  High,
} ErrorCorrectionLevel;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * A function that can be used for convenient access to the function
 * `create_secret`, by providing a default of `32` to the `length` parameter.
 */
const char *create_secret(uint8_t len);

#if defined(DEFINE_QRCODE)
/**
 * A function that can be used for convenient access to the function
 * `qr_code`, by providing a default of 200 to the `width` parameter, 200
 * to the `height` parameter, and `ErrorCorrectionLevel::Medium` to the `level` parameter.
 */
const char *qr_code(const char *secret,
                    const char *name,
                    const char *title,
                    uint32_t witdh,
                    uint32_t height,
                    enum ErrorCorrectionLevel level);
#endif

/**
 * # Safety
 * A function that can be used for convenient access to the function
 * `qr_code_url`, by providing a default of 200 to the `width` parameter, 200
 * to the `height` parameter, and `ErrorCorrectionLevel::Medium` to the `level` parameter.
 */
const char *qr_code_url(const char *secret,
                        const char *name,
                        const char *title,
                        uint32_t witdh,
                        uint32_t height,
                        enum ErrorCorrectionLevel level);

/**
 * # Safety
 * A function that can be used for convenient access to the function
 * `get_code`, by providing a default of the current time to the
 * `times_slice` parameter.
 */
const char *get_code(const char *secret, uint64_t time_slice);

/**
 * # Safety
 * A function that can be used for convenient access to the function
 * `verify_code`, by providing a default of 0 to the `discrepancy` parameter,
 * and the current time to the `times_slice` parameter.
 */
bool verify_code(const char *secret, const char *code, uint64_t discrepancy, uint64_t time_slice);

/**
 * # Safety
 * A function that can be used for free returnd to C string
 * `str`, the string which be passed to outside
 */
void free_str(char *str);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus
