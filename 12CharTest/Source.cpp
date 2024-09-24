/*
 * Source.cpp
 *
 *  Created on: Jul 6, 2023
 *      Author: Ramnath
 */

#include <stdio.h>

#include <iostream>
#include <vector>
using namespace std;

int main()
{
	string szPassword;
	std::vector<string> arrPassword;

	for(int a = 0; a < 26; a++)
	{
		for(int b = 0; b < 26; b++)
		{
			for(int c = 0; c < 26; c++)
			{
				for(int d = 0; d < 26; d++)
				{
					for(int e = 0; e < 26; e++)
					{
						for(int f = 0; f < 26; f++)
						{
							for(int g = 0; g < 26; g++)
							{
								for(int h = 0; h < 26; h++)
								{
									for(int i = 0; i < 26; i++)
									{
										for(int j = 0; j < 26; j++)
										{
											for(int k = 0; k < 26; k++)
											{
												for(int l = 0; l < 26; l++)
												{
													szPassword[0] = 'a' + a;
													szPassword[1] = 'a' + b;
													szPassword[2] = 'a' + c;
													szPassword[3] = 'a' + d;
													szPassword[4] = 'a' + e;
													szPassword[5] = 'a' + f;
													szPassword[6] = 'a' + g;
													szPassword[7] = 'a' + h;
													szPassword[8] = 'a' + i;
													szPassword[9] = 'a' + j;
													szPassword[10] = 'a' + k;
													szPassword[11] = 'a' + l;
													arrPassword.push_back(szPassword);
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return 0;
}
