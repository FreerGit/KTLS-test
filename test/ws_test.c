#include "testlib.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

int global_total_tests;
int global_failed_tests;

int main() {

  int result = (global_failed_tests != 0);

  printf("%s: %d/%d passed.\e[0m\n",
         result ? "\x1B[31mUnit Tests Failed" : "\x1B[32mUnit Tests Successful",
         global_total_tests - global_failed_tests,
         global_total_tests);
}
