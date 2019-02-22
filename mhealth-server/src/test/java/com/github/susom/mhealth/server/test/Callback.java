package com.github.susom.mhealth.server.test;

import java.util.function.Consumer;
import org.hamcrest.Description;
import org.mockito.ArgumentMatcher;

/**
 * This is a helper class to make stubbing asynchronous methods
 * easier. You can invoke callback handlers like so:
 * <p>
 *   {@code doNothing().when(mock).foo(argThat(new Callback<>(h -> h.handle(Future.succeededFuture("yay")))));}
 * </p>
 */
public class Callback<T> extends ArgumentMatcher<T> {
  private Consumer<T>[] argHandler = null;
  private int call = 0;

  @SafeVarargs
  public Callback(Consumer<T>... argHandler) {
    this.argHandler = argHandler;
  }

  @SuppressWarnings("unchecked")
  public boolean matches(Object argument) {
    if (argHandler != null) {
      if (call > argHandler.length - 1) {
        argHandler[argHandler.length - 1].accept((T) argument);
      } else {
        argHandler[call++].accept((T) argument);
      }
    }
    return true;
  }

  public void describeTo(Description description) {
    description.appendText("<Callback argument>");
  }
}
