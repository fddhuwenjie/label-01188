#include <iostream>
#include <string>
#include "math_utils.h"
#include "hill.h"
#include "vigenere.h"
#include "columnar.h"
#include "analysis.h"

using namespace std;

int main() {
    string plain = "CONFIDENTIALINFORMATIONAPPLIEDCRYPTOGRAPHYCURRICULUMSTARTSMONDAYAFTERNOON";
    int hillKey[3][3] = {{11,2,19},{3,7,4},{5,8,2}};
    string vigKey = "KEY";

    // Hill encrypt
    string c1 = hillEnc(plain, hillKey);
    cout << "C1 (Hill): " << c1 << " len=" << c1.length() << "\n";

    // Vig encrypt
    string c2 = vigEnc(c1, vigKey);
    cout << "C2 (Vig):  " << c2 << " len=" << c2.length() << "\n";

    // Col encrypt with same key "KEY"
    string c3_same = colEnc(c2, vigKey);
    cout << "C3 (Col key=KEY): " << c3_same << " len=" << c3_same.length() << "\n";

    // Try different col keys
    string expected = "EJBUJFNHQQRELMKPNIRQMSBPKVIZVLKSIYHCLGVFRITPEDFEFMQPEIWUKQHYKTIVUVSGQEJYDVH";
    cout << "Expected:          " << expected << " len=" << expected.length() << "\n";
    cout << "Match same key: " << (c3_same == expected ? "YES" : "NO") << "\n\n";

    // Try all 6 permutations of 3-letter keys
    string letters = "KEY";
    sort(letters.begin(), letters.end()); // EKY
    do {
        string c3 = colEnc(c2, letters);
        if (c3 == expected) {
            cout << "MATCH with col key: " << letters << "\n";
        }
    } while (next_permutation(letters.begin(), letters.end()));

    // Also try independent col keys - all 3! permutations of {0,1,2}
    cout << "\nTrying all permutation-based col keys:\n";
    for (int a = 0; a < 3; a++)
        for (int b = 0; b < 3; b++)
            for (int c = 0; c < 3; c++) {
                if (a==b || a==c || b==c) continue;
                string colKey(3, ' ');
                colKey[a] = 'A'; colKey[b] = 'B'; colKey[c] = 'C';
                string c3 = colEnc(c2, colKey);
                if (c3 == expected) {
                    cout << "  MATCH col key: " << colKey << " (perm " << a << b << c << ")\n";
                }
            }

    // Friedman on C2
    cout << "\nFriedman on C2:\n";
    auto fr = friedmanTest(c2, 6);
    for (auto& p : fr)
        cout << "  m=" << p.first << " IC=" << p.second << "\n";

    // Freq analysis on C2
    cout << "\nFreq key from C2 (m=3): " << deriveVigKeyByFrequency(c2, 3) << "\n";

    return 0;
}
