#pragma once
/*
 * BSD license by inclusion of servparse.cpp from NetBSD,
 * see the file servparse.cpp for details.  This file
 * assumes the most permissive available and applicable 
 * license given the restrictions therein.
 */

#include "sinsp.h"
#include <string>
using namespace std;

class service {
	public:
		static string findByPort(int port, string type/* = "tcp"*/);
		static int findByName(string name);

		// These will typecheck whats coming in and return a
		// name (either what came in or converted)
		static string toName(string in);
		static int toPort(string in);
};
