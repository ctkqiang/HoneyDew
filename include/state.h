#pragma once

#ifndef STATE_H
#define STATE_H

typedef enum {
  NO_STATE,
  IDLE_STATE,
  RUNNING_STATE,
  STOPPED_STATE,
  PANIC_STATE
} state_condition;

#endif