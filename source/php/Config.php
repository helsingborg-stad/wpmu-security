<?php

namespace WPMUSecurity;

class Config
{
  public function enableHsts():bool
  {
    return true;
  }

  public function enableCors():bool
  {
    return true;
  }

  public function getHstsMaxAge():int
  {
    return 31536000;
  }
}