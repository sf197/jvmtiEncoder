#include <jvmti.h>
#include <jni.h>
#include <stdio.h>
#include <cstring>
#include "aes/aes.h"
#include "stdlib.h" 
#include "org_jarEncoder_ByteCodeEncryptor.h"
 
#define MAX_LEN (2*1024*1024)
#define ENCRYPT 0
#define DECRYPT 1
#define AES_KEY_SIZE 256
#define READ_LEN 10

//AES_IV
static unsigned char AES_IV[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
//AES_KEY
static unsigned char AES_KEY[32] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71,
		0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c,
		0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf,
		0xf4 };
 
JNIEXPORT jbyteArray JNICALL Java_org_jarEncoder_ByteCodeEncryptor_encrypt(JNIEnv * env, jclass cla, jbyteArray text)
{
	//check input data
	unsigned int len = (unsigned int) (env->GetArrayLength(text));
	if (len <= 0 || len >= MAX_LEN) {
		return NULL;
	}

	char *data = (char*) env->GetByteArrayElements(text, NULL);
	if (!data) {
		return NULL;
	}

	//计算填充长度，当为加密方式且长度不为16的整数倍时，则填充，与3DES填充类似(DESede/CBC/PKCS5Padding)
	unsigned int mode = ENCRYPT;
	unsigned int rest_len = len % AES_BLOCK_SIZE;
	unsigned int padding_len = (
			(ENCRYPT == mode) ? (AES_BLOCK_SIZE - rest_len) : 0);
	unsigned int src_len = len + padding_len;

	//设置输入
	unsigned char *input = (unsigned char *) malloc(src_len);
	memset(input, 0, src_len);
	memcpy(input, data, len);
	if (padding_len > 0) {
		memset(input + len, (unsigned char) padding_len, padding_len);
	}
	//data不再使用
	env->ReleaseByteArrayElements(text, (jbyte *)data, 0);

	//设置输出Buffer
	unsigned char * buff = (unsigned char*) malloc(src_len);
	if (!buff) {
		free(input);
		return NULL;
	}
	memset(buff, 0, src_len);

	//set key & iv
	unsigned int key_schedule[AES_BLOCK_SIZE * 4] = { 0 }; //>=53(这里取64)
	aes_key_setup(AES_KEY, key_schedule, AES_KEY_SIZE);

	//执行加解密计算(CBC mode)
	if (mode == ENCRYPT) {
		aes_encrypt_cbc(input, src_len, buff, key_schedule, AES_KEY_SIZE,
				AES_IV);
	} else {
		aes_decrypt_cbc(input, src_len, buff, key_schedule, AES_KEY_SIZE,
				AES_IV);
	}

	//解密时计算填充长度
	if (ENCRYPT != mode) {
		unsigned char * ptr = buff;
		ptr += (src_len - 1);
		padding_len = (unsigned int) *ptr;
		if (padding_len > 0 && padding_len <= AES_BLOCK_SIZE) {
			src_len -= padding_len;
		}
		ptr = NULL;
	}

	//设置返回变量
	jbyteArray bytes = env->NewByteArray(src_len);
	env->SetByteArrayRegion(bytes, 0, src_len, (jbyte*) buff);

	//内存释放
	free(input);
	free(buff);

	return bytes;
}

unsigned char *decode(char *data,int len,int *result_len)
{
	//计算填充长度，当为加密方式且长度不为16的整数倍时，则填充，与3DES填充类似(DESede/CBC/PKCS5Padding)
	unsigned int mode = DECRYPT;
	unsigned int rest_len = len % AES_BLOCK_SIZE;
	unsigned int padding_len = (
			(ENCRYPT == mode) ? (AES_BLOCK_SIZE - rest_len) : 0);
	unsigned int src_len = len + padding_len;

	//设置输入
	unsigned char *input = (unsigned char *) malloc(src_len);
	memset(input, 0, src_len);
	memcpy(input, data, len);
	if (padding_len > 0) {
		memset(input + len, (unsigned char) padding_len, padding_len);
	}
	

	//设置输出Buffer
	unsigned char * buff = (unsigned char*) malloc(src_len);
	if (!buff) {
		free(input);
		return NULL;
	}
	memset(buff, 0, src_len);

	//set key & iv
	unsigned int key_schedule[AES_BLOCK_SIZE * 4] = { 0 }; //>=53(这里取64)
	aes_key_setup(AES_KEY, key_schedule, AES_KEY_SIZE);

	//执行加解密计算(CBC mode)
	if (mode == ENCRYPT) {
		aes_encrypt_cbc(input, src_len, buff, key_schedule, AES_KEY_SIZE,
				AES_IV);
	} else {
		aes_decrypt_cbc(input, src_len, buff, key_schedule, AES_KEY_SIZE,
				AES_IV);
	}

	//解密时计算填充长度
	if (ENCRYPT != mode) {
		unsigned char * ptr = buff;
		ptr += (src_len - 1);
		padding_len = (unsigned int) *ptr;
		if (padding_len > 0 && padding_len <= AES_BLOCK_SIZE) {
			src_len -= padding_len;
		}
		ptr = NULL;
	}
	*result_len = src_len;

	//内存释放
	free(input);

	return buff;
}
 
void JNICALL ClassDecryptHook(
    jvmtiEnv *jvmti_env,
    JNIEnv* jni_env,
    jclass class_being_redefined,
    jobject loader,
    const char* name,
    jobject protection_domain,
    jint class_data_len,
    const unsigned char* class_data,
    jint* new_class_data_len,
    unsigned char** new_class_data
)
{
    unsigned char* _data = (unsigned char*) malloc(class_data_len);
	if (!_data) {
		return;
	}
 
    if (name && strncmp(name, package_prefix, compare_length) == 0)
    {
        for (int i = 0; i < class_data_len; i++)
        {
            _data[i] = class_data[i];
        }
		int new_data_len = 0;
        unsigned char* _result = decode((char*)_data,class_data_len,&new_data_len);
		*new_class_data_len = new_data_len;
		jvmti_env->Allocate(new_data_len, new_class_data);
		*new_class_data = _result;
    }
    else {
        for (int i = 0; i < class_data_len; i++)
        {
            _data[i] = class_data[i];
        }
		*new_class_data_len = class_data_len;
		jvmti_env->Allocate(class_data_len, new_class_data);
		*new_class_data = _data;
    }
}
 
JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved)
{
 
    jvmtiEnv *jvmti;
    jint ret = vm->GetEnv((void **)&jvmti, JVMTI_VERSION);
    if (JNI_OK != ret)
    {
        printf("ERROR: Unable to access JVMTI!\n");
        return ret;
    }
    jvmtiCapabilities capabilities;
    (void)memset(&capabilities, 0, sizeof(capabilities));
 
    capabilities.can_generate_all_class_hook_events = 1;
    capabilities.can_tag_objects = 1;
    capabilities.can_generate_object_free_events = 1;
    capabilities.can_get_source_file_name = 1;
    capabilities.can_get_line_numbers = 1;
    capabilities.can_generate_vm_object_alloc_events = 1;
 
    jvmtiError error = jvmti->AddCapabilities(&capabilities);
    if (JVMTI_ERROR_NONE != error)
    {
        printf("ERROR: Unable to AddCapabilities JVMTI!\n");
        return error;
    }
 
    jvmtiEventCallbacks callbacks;
    (void)memset(&callbacks, 0, sizeof(callbacks));
 
    callbacks.ClassFileLoadHook = &ClassDecryptHook;
    error = jvmti->SetEventCallbacks(&callbacks, sizeof(callbacks));
    if (JVMTI_ERROR_NONE != error)
    {
        printf("ERROR: Unable to SetEventCallbacks JVMTI!\n");
        return error;
    }
 
    error = jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_CLASS_FILE_LOAD_HOOK, NULL);
    if (JVMTI_ERROR_NONE != error)
    {
        printf("ERROR: Unable to SetEventNotificationMode JVMTI!\n");
        return error;
    }
 
    return JNI_OK;
}