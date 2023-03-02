#ifndef __CICVD_CRYPTO_H__
#define __CICVD_CRYPTO_H__

#ifdef __cplusplus
extern "C" {
#endif
#pragma pack(1)

/**
 * @brief The application id structure.
 */
typedef struct cicvd_app_id
{
    unsigned char private_id[32]; //私有ID-A
    unsigned char public_id[32];  //公有ID-M
}cicvd_app_id;

/**
 * @brief The CICVD crypto context structure.
 */
typedef struct cicvd_crypto_context
{
    cicvd_app_id appid;                                 /*!< Application id*/
    unsigned char seed[32];                             /*!<  seed for derive sessionkey*/
    unsigned char sessionkey[16];                       /*!<  Session key*/
}cicvd_crypto_context;

#define     CICVD_CRYPTO_ERR_SUCCESS                    0                                           //成功
#define     CICVD_CRYPTO_ERR_BASE                       0xF0000000  
#define     CICVD_CRYPTO_ERR_INVALID_PARAMETER          CICVD_CRYPTO_ERR_BASE + 1                   //参数错误
#define     CICVD_CRYPTO_ERR_CORRUPTION_DETECTED        CICVD_CRYPTO_ERR_BASE + 2                   //cicvdcrypto库错误
#define     CICVD_CRYPTO_ERR_CRYPT                      CICVD_CRYPTO_ERR_BASE + 3                   //内部加密算法执行失败
#define     CICVD_CRYPTO_ERR_WRITEFILE_IO               CICVD_CRYPTO_ERR_BASE + 4                   //文件写IO错误
#define     CICVD_CRYPTO_ERR_FILE_HEADER                CICVD_CRYPTO_ERR_BASE + 5                   //文件header错误
#define     CICVD_CRYPTO_ERR_MALLOC                     CICVD_CRYPTO_ERR_BASE + 6                   //分配内存失败
#define     CICVD_CRYPTO_ERR_READFILE_IO                CICVD_CRYPTO_ERR_BASE + 7                   //文件读IO错误
#define     CICVD_CRYPTO_ERR_FILE_CIPHER                CICVD_CRYPTO_ERR_BASE + 8                   //文件的密文数据错误
#define     CICVD_CRYPTO_ERR_OFFSET_INVALID             CICVD_CRYPTO_ERR_BASE + 9                   //无效的偏移量
#define     CICVD_CRYPTO_ERR_SE_PIN_INVALID             CICVD_CRYPTO_ERR_BASE + 10                  //Verify SE PIN wrong
#define     CICVD_CRYPTO_ERR_SE_AES_FAILED              CICVD_CRYPTO_ERR_BASE + 11                  //SE AES calcuate failed
#define     CICVD_CRYPTO_DERIVE_KEY_FAILED              CICVD_CRYPTO_ERR_BASE + 12   

#define APP_ID_PUBLIC_LEN                   32
#define APP_ID_PRIVATE_LEN                  32  
#define CRYPTO_FILE_HEADER_LEN              32
#define AES_BLOCK_SIZE                      16

/**
 * Padding Mode
*/
#define NO_PADDING                        0
#define ISO9797_1_M1_PADDING              1
#define ISO9797_1_M2_PADDING              2
/**
 * \brief 初始化接口，应用调用加密解密功能之前需要调用初始化接口获取加解密上下文
 * 
 * \param  ctx  加解密上下文 不能为NULL 初始化成功后返回上下文
 * \param  private_id 私有ID-A 长度为
 * \param  public_id 公共ID-M 长度为
 * 
 * \return 0 成功 
 */
unsigned int cicvd_crypto_init(cicvd_crypto_context* ctx, unsigned char* private_id, unsigned char* public_id);

/**
 * @brief 释放加解密上下文
 * 
 * @param ctx cicvd_crypto_init获得的上下文
 * @return 0 成功
 */
unsigned int cicvd_crypto_free(cicvd_crypto_context* ctx);


/**
 * @brief 日志加密
 * 
 * @param ctx       IN     cicvd_crypto_init获得的上下文
 * @param input     IN     日志明文数据
 * @param inlen     IN     日志明文的长度 字节
 * @param output    OUT    密文输出缓冲区
 * @param outlen    IN/OUT 传入密文输出缓冲区的长度，输出密文输出的长度 字节
 * @return 0        成功 
 */
unsigned int cicvd_crypto_log_enc(cicvd_crypto_context* ctx, unsigned char* input, int inlen, unsigned char* output, int* outlen);

/**
 * @brief 日志解密
 * 
 * @param ctx       IN     cicvd_crypto_init获得的上下文
 * @param input     IN     日志密文数据
 * @param inlen     IN     日志密文数据长度 字节
 * @param output    OUT    日志明文输出缓冲区
 * @param outlen    IN/OUT 传入明文缓冲区的长度，输出明文的长度 字节
 * @return 0        成功
 */
unsigned int cicvd_crypto_log_dec(cicvd_crypto_context* ctx, unsigned char* input, int inlen, unsigned char* output, int* outlen);


unsigned int cicvd_crypto_get_key_neusoft(cicvd_crypto_context* ctx, char* key, int* keylen);

#pragma pack()
#ifdef __cplusplus
}
#endif

#endif //__CICVD_CRYPTO_H__