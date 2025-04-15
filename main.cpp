#include <iostream>
#include "math_utils.h" // 包含静态库头文件

int main() {
    std::cout << "Add: 3 + 5 = " << add(3, 5) << std::endl;
    std::cout << "Subtract: 8 - 2 = " << subtract(8, 2) << std::endl;
    std::cout << "Multiply: 4 * 6 = " << multiply(4, 6) << std::endl;
    std::cout << "Divide: 10 / 3 = " << divide(10, 3) << std::endl;
    return 0;
}