This is a simplified version of simpleserial-aes for STM32F215 (w/ hardware crypto coprocessor CRYP),
which calls CRYP directly without going through HAL abstraction, resulting in much shorter traces.

Additionally, serial processing of multiple messages has been added using a plaintext queue.
This mechanism allows to capture multiple encryptions, but each of them has its own trigger
period. This is not so helpful when ChipWhisperer is used as the scope, but is really helpful
with an external scope, when capturing multiple encryptions in a single trace buffer.

No need to provide PLATFORM or CRYPTO_TARGET, STM32F2 is already specified in Makefile.platform
