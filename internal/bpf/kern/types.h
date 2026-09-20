#pragma once

enum lb_algorithm {
  RANDOM = 1,
  HASH = 2,
};

volatile enum lb_algorithm lb_algo;

enum backend_selection_error {
  ERR_LISTENER_NOT_FOUND = 1,
  ERR_NO_BACKENDS = 2,
  ERR_UNKNOWN_ALGORITHM = 3,
};
