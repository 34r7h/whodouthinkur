#include <stdio.h>
#include <string.h>
#include <stdint.h>

// Simulate the MAYO packing functions
void pack_m_vecs(const uint64_t *in, unsigned char *out, int vecs, int m) {
    const int m_vec_limbs = (m + 15) / 16;
    unsigned char *_in = (unsigned char *) in;
    printf("pack_m_vecs: vecs=%d, m=%d, m_vec_limbs=%d\n", vecs, m, m_vec_limbs);
    printf("pack_m_vecs: copying %d bytes per vec\n", m/2);
    printf("pack_m_vecs: total output size: %d bytes\n", vecs * m/2);
    
    for (int i = 0; i < vecs; i++) {
        printf("Vector %d: copying from offset %d to offset %d, size %d\n", 
               i, i*m_vec_limbs*8, i*m/2, m/2);
        memmove(out + (i*m/2), _in + i*m_vec_limbs*sizeof(uint64_t), m/2);
    }
}

void unpack_m_vecs(const unsigned char *in, uint64_t *out, int vecs, int m) {
    const int m_vec_limbs = (m + 15) / 16;
    unsigned char *_out = (unsigned char *) out;
    uint64_t tmp[ (256 + 15) / 16] = {0}; // M_MAX simulation
    printf("unpack_m_vecs: vecs=%d, m=%d, m_vec_limbs=%d\n", vecs, m, m_vec_limbs);
    printf("unpack_m_vecs: reading %d bytes per vec\n", m/2);
    printf("unpack_m_vecs: writing %d bytes per vec\n", m_vec_limbs*8);
    
    for (int i = vecs-1; i >= 0; i--) {
        printf("Vector %d: reading from offset %d, writing to offset %d\n",
               i, i*m/2, i*m_vec_limbs*8);
        memcpy(tmp, in + i*m/2, m/2);
        memcpy(_out + i*m_vec_limbs*sizeof(uint64_t), tmp, m_vec_limbs*sizeof(uint64_t));
    }
}

int main() {
    // Test with MAYO-5 parameters
    int m = 196;  // MAYO-5 m parameter
    int o = 18;   // MAYO-5 o parameter
    
    printf("=== MAYO-5 PARAMETER ANALYSIS ===\n");
    printf("m = %d\n", m);
    printf("o = %d\n", o);
    
    // P3 calculation
    int P3_vecs = (o * (o + 1)) / 2;
    printf("P3 upper triangular vectors: %d\n", P3_vecs);
    
    int m_vec_limbs = (m + 15) / 16;
    printf("m_vec_limbs = (%d + 15) / 16 = %d\n", m, m_vec_limbs);
    
    // Size analysis
    int packed_size_per_vec = m / 2;
    int unpacked_size_per_vec = m_vec_limbs * 8;
    
    printf("\nSIZE ANALYSIS:\n");
    printf("Packed size per vector: %d bytes\n", packed_size_per_vec);
    printf("Unpacked size per vector: %d bytes\n", unpacked_size_per_vec);
    printf("Size difference per vector: %d bytes\n", unpacked_size_per_vec - packed_size_per_vec);
    
    int total_packed = P3_vecs * packed_size_per_vec;
    int total_unpacked = P3_vecs * unpacked_size_per_vec;
    
    printf("\nTOTAL P3 SIZES:\n");
    printf("Total packed P3 size: %d bytes\n", total_packed);
    printf("Total unpacked P3 size: %d bytes\n", total_unpacked);
    printf("Total size difference: %d bytes\n", total_unpacked - total_packed);
    
    // Simulate packing/unpacking
    printf("\n=== SIMULATION ===\n");
    uint64_t test_data[13*171] = {0}; // Enough space for unpacked
    unsigned char packed_data[171*98] = {0}; // Enough space for packed
    
    // Fill test data with pattern
    for (int i = 0; i < 13*171; i++) {
        test_data[i] = 0x123456789ABCDEF0ULL + i;
    }
    
    printf("Before packing - first few uint64_t values:\n");
    for (int i = 0; i < 5; i++) {
        printf("test_data[%d] = 0x%016llx\n", i, (unsigned long long)test_data[i]);
    }
    
    pack_m_vecs(test_data, packed_data, P3_vecs, m);
    
    printf("\nPacked data (first 20 bytes as hex):\n");
    for (int i = 0; i < 20; i++) {
        printf("%02x", packed_data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
    
    // Check for trailing zeros in packed data
    int trailing_zeros = 0;
    for (int i = total_packed - 1; i >= 0; i--) {
        if (packed_data[i] == 0) {
            trailing_zeros++;
        } else {
            break;
        }
    }
    printf("Trailing zeros in packed data: %d bytes\n", trailing_zeros);
    
    return 0;
} 