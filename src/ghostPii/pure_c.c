#include <stdio.h>

long long int c_pow_c(long long unsigned base, long long unsigned exp, long long unsigned mod){
  base = base % mod;
  exp = exp % (mod-1);
  long long unsigned temp = 1;
  while (exp > 0){
    if ((exp%2) > 0){
      temp = (temp*base) % mod;
      exp -= 1;
    }
    base = (base*base) % mod;
    exp /= 2;
  }
  return temp % mod;
}

long long int pow_no_of_c(long long unsigned base, long long unsigned exp, long long unsigned mod){
    long long int result = 1;
    for(int i = 0; i < exp; ++i){
        result = (result*base)%mod;
    }
    return result;
}

int main(int argc, const char* argv[]){
    return 0;
}
