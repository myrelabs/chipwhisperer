#include "simpleserial.h"
#include "sign.h"


#define MAX_MESSAGE_LEN  32

uint8_t qdsa_set_private_key(uint8_t *pt);
uint8_t qdsa_get_public_key(uint8_t *pt);

uint8_t qdsa_set_message(uint8_t *pt);
uint8_t qdsa_gen_sig(uint8_t *pt);
uint8_t qdsa_get_sig(uint8_t *pt);
uint8_t qdsa_ver_sig(uint8_t *pt);



unsigned char private_key[64];
unsigned char public_key[32];
unsigned char signed_message_buffer[64+MAX_MESSAGE_LEN];
unsigned long long  message_length;



uint8_t qdsa_set_private_key(uint8_t *pt)
{
    uint8_t  ret;
    unsigned int i;

    for (i=0; i < 64 ; i++)
    	private_key[i] = pt[i];
    	
    ret = keypair(public_key, private_key);
    return ret;
}



uint8_t qdsa_get_public_key(uint8_t *pt)
{
    simpleserial_put('r', 32, public_key);
    return 0;
}



uint8_t qdsa_set_message(uint8_t *pt)
{
    unsigned int i;
    
    if (pt[0] > MAX_MESSAGE_LEN)
    	message_length = MAX_MESSAGE_LEN;
    else
    	message_length = pt[0];    
       
    for (i=0; i < message_length; i++)
    	signed_message_buffer[64+i] = pt[1+i];
    	
    return 0;	
}



uint8_t qdsa_gen_sig(uint8_t *pt)   
{
    uint8_t ret;
    unsigned long long  signed_message_length;		
    ret = sign(signed_message_buffer, &signed_message_length, signed_message_buffer+64, message_length, public_key, private_key);
    
    return ret;
}



uint8_t qdsa_get_sig(uint8_t *pt)
{
    simpleserial_put('r', 64 + message_length, signed_message_buffer);
    return 0;
}



uint8_t qdsa_ver_sig(uint8_t *pt)
{
   uint8_t  ret;
   
   ret = verify(signed_message_buffer+64, message_length, signed_message_buffer, message_length + 64, public_key);  
   return ret;
}


