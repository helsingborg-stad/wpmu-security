<?php

namespace WPMUSecurity;

/**
 * Interface HookableInterface
 *
 * Represents a class that can register hooks with WordPress.
 */
interface HookableInterface
{
  /**
   * Register the hooks with WordPress.
   *
   * @return void
   */
  public function addHooks(): void;
}