// Przyklad.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
using namespace std;

int main()
{
	double liczba;
	cout << "Podaj liczbe:" << endl;
	cin >> liczba;
	cout << "sin(" << liczba << ")=" << sin(liczba) << endl;
	cout << "cos(" << liczba << ")=" << cos(liczba) << endl;

	system("pause");
	return 0;
}

