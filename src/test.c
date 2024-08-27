#include<stdio.h>

//caculate f(x) = ax^2 + bx + c;
//int First(int a, int x);
//int Second(int b, int x);
//int Third(int c, int x);

int a = 2, b = 3, c = 5;
int First(int x) {
	return x * x * a;
}

int Second(int x) {
	return b * x;
}

int Third(int x) {
	return x * 0 + c;
}



int main() {
	int sum = 0, first = 0, second = 0, third = 0;	
	int x = 2;
	first = First(x);
	second = Second(x);
	third = Third(x);
	sum += first + second + third;
	return sum;
}

