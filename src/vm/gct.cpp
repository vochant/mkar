#include "vm/gct.hpp"

#include "vm/vm.hpp"
#include "vm_error.hpp"

MpcEnum::MpcEnum() {}

std::map<std::string, std::shared_ptr<MpcEnum>> GENT;