/*
 * Source.cpp
 *
 *  Created on: Apr 13, 2023
 *      Author: Ramnath
 */
#include <stdio.h>

#include <iostream>
#include <string>
#include <vector>
#include <map>
using namespace std;

int main()
{
	getchar();
	vector<wstring> wszvecData;
	wszvecData.push_back(L"Hello");
	wszvecData.push_back(L" ");
	wszvecData.push_back(L"World");
	for(auto data1 : wszvecData)
	{
		wcout <<  data1;
	}
}
