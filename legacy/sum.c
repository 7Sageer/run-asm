// sum.c
long sum_array(long *arr, int count) {
    long sum = 0;
    for (int i = 0; i < count; i++) {
        sum += arr[i];
    }
    return sum;
} 