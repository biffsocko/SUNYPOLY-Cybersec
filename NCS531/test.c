#include<stdio.h>
#include<stdlib.h>

int main(){
    char *kernel_data_addr = (char*)0xf93a7000;
    char kernel_data = *kernel_data_addr;
    printf("I have reached here.\n");
    return 0;
}
