package com.scaler.userService.repositories;

import com.scaler.userService.models.Session;
import com.scaler.userService.models.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SessionRepository extends JpaRepository<User,Long>
{
  Session save(Session session);

}
