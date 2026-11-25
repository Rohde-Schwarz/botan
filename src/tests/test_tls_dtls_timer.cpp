/*
* (C) 2026 Jack Lloyd
* (C) 2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_DTLS_13)

   #include <botan/tls_magic.h>
   #include <botan/internal/tls_timer_dtls13.h>
   #include <algorithm>

namespace Botan_Tests {

namespace {

class Timer_Callbacks final : public Botan::TLS::Callbacks {
   public:
      void tls_emit_data(std::span<const uint8_t> /*data*/) override {}

      void tls_record_received(uint64_t /*seq*/, std::span<const uint8_t> /*data*/) override {}

      void tls_alert(Botan::TLS::Alert /*alert*/) override {}

      uint64_t tls_current_monotonic_clock_ms() override { return m_now_ms; }

      void tls_register_deferred_operation(uint64_t monotonic_delay_ms, std::function<void()> op) override {
         const uint64_t deadline_ms = tls_current_monotonic_clock_ms() + monotonic_delay_ms;
         m_deferred_ops.emplace_back(Deferred_Operation{
            .deadline_ms = deadline_ms,
            .op = std::move(op),
         });
      }

      void set_clock_forward(std::chrono::milliseconds delta) { m_now_ms += delta.count(); }

      void advance(std::chrono::milliseconds delta) {
         m_now_ms += delta.count();

         // Collect the due operations before invoking them, because an invoked
         // operation may register new deferred operations (e.g. the retransmission
         // timer re-arms itself) and thereby invalidate iterators of m_deferred_ops.
         std::vector<std::function<void()>> due_ops;
         std::erase_if(m_deferred_ops, [this, &due_ops](Deferred_Operation& op) {
            if(op.deadline_ms <= m_now_ms) {
               due_ops.emplace_back(std::move(op.op));
               return true;
            }
            return false;
         });

         for(const auto& op : due_ops) {
            op();
         }
      }

      [[nodiscard]] std::function<void()> get_next_scheduled_operation() const {
         const auto next_op = std::min_element(
            m_deferred_ops.begin(), m_deferred_ops.end(), [](const Deferred_Operation& a, const Deferred_Operation& b) {
               return a.deadline_ms < b.deadline_ms;
            });

         if(next_op == m_deferred_ops.end()) {
            throw Botan_Tests::Test_Error("No scheduled operations");
         }

         return next_op->op;
      }

      [[nodiscard]] size_t deferred_op_count() const { return m_deferred_ops.size(); }

      [[nodiscard]] uint64_t next_remaining_ms() const {
         const auto next_op = std::min_element(
            m_deferred_ops.begin(), m_deferred_ops.end(), [](const Deferred_Operation& a, const Deferred_Operation& b) {
               return a.deadline_ms < b.deadline_ms;
            });

         if(next_op == m_deferred_ops.end()) {
            throw Botan_Tests::Test_Error("No scheduled operations");
         }

         return next_op->deadline_ms > m_now_ms ? next_op->deadline_ms - m_now_ms : 0;
      }

   private:
      struct Deferred_Operation {
            uint64_t deadline_ms;
            std::function<void()> op;
      };

      uint64_t m_now_ms = 0;
      std::vector<Deferred_Operation> m_deferred_ops;
};

class Timer_Operation final {
   public:
      Timer_Operation() = default;
      Timer_Operation(const Timer_Operation&) = delete;
      Timer_Operation& operator=(const Timer_Operation&) = delete;
      Timer_Operation(Timer_Operation&&) = default;
      Timer_Operation& operator=(Timer_Operation&&) = default;
      ~Timer_Operation() = default;

      std::function<void()> callback() {
         return [this]() { ++m_runs; };
      }

      // NOLINTNEXTLINE(*-explicit-conversions)
      operator bool() const { return m_runs > 0; }

      // NOLINTNEXTLINE(*-explicit-conversions)
      operator uint32_t() const { return m_runs; }

   private:
      uint32_t m_runs = 0;
};

class Retransmission_Test_Policy final : public Botan::TLS::Policy {
   public:
      Retransmission_Test_Policy(std::chrono::milliseconds initial_timeout,
                                 std::chrono::milliseconds maximum_timeout,
                                 std::optional<std::chrono::milliseconds> flight_timeout,
                                 std::optional<size_t> maximum_retransmissions) :
            m_initial_timeout(initial_timeout),
            m_maximum_timeout(maximum_timeout),
            m_flight_timeout(flight_timeout),
            m_maximum_retransmissions(maximum_retransmissions) {}

      size_t dtls_initial_timeout() const override { return m_initial_timeout.count(); }

      size_t dtls_maximum_timeout() const override { return m_maximum_timeout.count(); }

      std::optional<size_t> dtls_flight_timeout() const override {
         // TODO(C++23): std::optional::transform
         if(m_flight_timeout.has_value()) {
            return m_flight_timeout->count();
         }
         return std::nullopt;
      }

      std::optional<size_t> dtls_maximum_retransmissions() const override { return m_maximum_retransmissions; }

   private:
      std::chrono::milliseconds m_initial_timeout;
      std::chrono::milliseconds m_maximum_timeout;
      std::optional<std::chrono::milliseconds> m_flight_timeout;
      std::optional<size_t> m_maximum_retransmissions;
};

using namespace Botan;
using namespace Botan::TLS;
using namespace std::chrono_literals;

std::vector<Test::Result> singleshot_timer() {
   return {
      CHECK("deferred operation runs after deadline",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               Timer_Operation op;

               auto token = SingleshotTimer::start(cb, 100ms, op.callback());

               result.test_is_true("token is valid", token);
               result.test_is_true("token is armed", token.armed());
               result.test_u64_eq("remaining time is the full delay", token.remaining(*cb).value_or(-1ms).count(), 100);

               result.test_is_false("did not run yet", op);

               cb->set_clock_forward(10ms);
               const auto early_op = cb->get_next_scheduled_operation();
               early_op();
               result.test_is_false("early invocation did not run operation", op);
               result.test_is_true("timer still armed after early invocation", token.armed());
               result.test_u64_eq("re-armed for remaining time", cb->next_remaining_ms(), 90);
               result.test_u64_eq(
                  "accessor also reports the re-armed remaining time", token.remaining(*cb).value_or(-1ms).count(), 90);
               const auto op_count_after_early = cb->deferred_op_count();
               early_op();
               result.test_sz_eq(
                  "duplicate early invocation did not schedule again", cb->deferred_op_count(), op_count_after_early);

               cb->advance(89ms);
               result.test_is_false("still didn't run yet", op);
               result.test_u64_eq("one millisecond of remaining time", token.remaining(*cb).value_or(-1ms).count(), 1);
               cb->advance(1ms);
               result.test_is_true("deferred operation ran", op);

               result.test_is_false("token is no longer valid", token);
               result.test_is_false("token is no longer armed", token.armed());
               result.test_is_false("no remaining time after the operation ran", token.remaining(*cb).has_value());
            }),

      CHECK("detached operation runs after deadline",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               Timer_Operation op;

               SingleshotTimer::start_detached(cb, 100ms, op.callback());

               result.test_is_false("did not run yet", op);

               cb->set_clock_forward(10ms);
               const auto early_op = cb->get_next_scheduled_operation();
               early_op();
               result.test_is_false("early invocation did not run operation", op);
               result.test_u64_eq("re-armed for remaining time", cb->next_remaining_ms(), 90);
               const auto op_count_after_early = cb->deferred_op_count();
               early_op();
               result.test_sz_eq(
                  "duplicate early invocation did not schedule again", cb->deferred_op_count(), op_count_after_early);

               cb->advance(89ms);
               result.test_is_false("still didn't run yet", op);
               cb->advance(1ms);
               result.test_is_true("deferred operation ran", op);
            }),

      CHECK("deferred operation runs only once, even when called multiple times",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               Timer_Operation op;

               auto token = SingleshotTimer::start(cb, 100ms, op.callback());

               result.test_is_false("did not run yet", op);

               cb->set_clock_forward(100ms);
               const auto scheduled_op = cb->get_next_scheduled_operation();
               result.test_is_true("remaining time is available at the deadline", token.remaining(*cb).has_value());
               result.test_u64_eq(
                  "remaining time clamps to zero at the deadline", token.remaining(*cb).value_or(-1ms).count(), 0);
               scheduled_op();
               result.test_is_true("deferred operation ran", op);
               scheduled_op();
               result.test_u32_eq("deferred operation ran only once", op, 1);
               result.test_is_false("no remaining time after the operation ran", token.remaining(*cb).has_value());

               cb->advance(100ms);
               result.test_u32_eq("deferred operation didn't run after deadline", op, 1);
            }),

      CHECK("detached operation runs only once, even when called multiple times",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               Timer_Operation op;

               SingleshotTimer::start_detached(cb, 100ms, op.callback());

               result.test_is_false("did not run yet", op);

               cb->set_clock_forward(100ms);
               const auto scheduled_op = cb->get_next_scheduled_operation();
               scheduled_op();
               result.test_is_true("deferred operation ran", op);
               scheduled_op();
               result.test_u32_eq("deferred operation ran only once", op, 1);

               cb->advance(100ms);
               result.test_u32_eq("deferred operation didn't run after deadline", op, 1);
            }),

      CHECK("deferred operation does not re-run after throwing an exception",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               uint32_t runs = 0;

               auto token = SingleshotTimer::start(cb, 100ms, [&runs] {
                  ++runs;
                  throw TLS_Exception(Alert::None, "operation failed");
               });

               result.test_is_true("token is armed", token.armed());

               cb->set_clock_forward(100ms);
               const auto scheduled_op = cb->get_next_scheduled_operation();
               result.test_throws<TLS_Exception>(
                  "operation threw an exception", "operation failed", [&] { scheduled_op(); });

               result.test_is_false("token is no longer armed", token.armed());
               result.test_is_false("no remaining time after the operation threw", token.remaining(*cb).has_value());

               scheduled_op();
               result.test_u32_eq("operation did not re-run when called again", runs, 1);

               cb->advance(100ms);
               result.test_u32_eq("operation did not re-run after the deadline", runs, 1);
            }),

      CHECK("detached operation does not re-run after throwing an exception",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               uint32_t runs = 0;

               SingleshotTimer::start_detached(cb, 100ms, [&runs] {
                  ++runs;
                  throw TLS_Exception(Alert::None, "operation failed");
               });

               cb->set_clock_forward(100ms);
               const auto scheduled_op = cb->get_next_scheduled_operation();
               result.test_throws<TLS_Exception>(
                  "operation threw an exception", "operation failed", [&] { scheduled_op(); });

               scheduled_op();
               result.test_u32_eq("operation did not re-run when called again", runs, 1);

               cb->advance(100ms);
               result.test_u32_eq("operation did not re-run after the deadline", runs, 1);
            }),

      CHECK("early invocation honours the fudge",
            [&](Test::Result& result) {
               constexpr auto delay = 100ms;
               const std::chrono::milliseconds fudge{DTLS_RETRANSMISSION_TIMER_FUDGE};

               // Invoking the deferred operation with more than the fudge time
               // remaining re-arms the timer for the rest of the original delay.
               {
                  auto cb = std::make_shared<Timer_Callbacks>();
                  Timer_Operation op;
                  auto token = SingleshotTimer::start(cb, delay, op.callback());

                  const auto above_fudge = delay - fudge - 1ms;
                  cb->set_clock_forward(above_fudge);
                  cb->get_next_scheduled_operation()();
                  result.test_is_false("invocation above the fudge did not run yet", op);
                  result.test_u64_eq(
                     "re-armed for the remaining time above the fudge", cb->next_remaining_ms(), fudge.count() + 1);
                  result.test_u64_eq("accessor also reports the remaining time above the fudge",
                                     token.remaining(*cb).value_or(-1ms).count(),
                                     fudge.count() + 1);

                  cb->advance(above_fudge);
                  result.test_is_true("re-armed timer fires at the original deadline", op);
                  result.test_is_false("timer is no longer armed", token.armed());
               }

               // Invoking the deferred operation within the fudge time runs it
               // immediately, as if the deadline had been reached.
               {
                  auto cb = std::make_shared<Timer_Callbacks>();
                  Timer_Operation op;
                  auto token = SingleshotTimer::start(cb, delay, op.callback());

                  cb->set_clock_forward(delay - fudge);
                  cb->get_next_scheduled_operation()();
                  result.test_is_true("invocation within the fudge runs immediately", op);
                  result.test_is_false("timer is no longer armed", token.armed());
                  result.test_is_false("no remaining time after the fudged invocation",
                                       token.remaining(*cb).has_value());
               }
            }),

      CHECK("deferred operation can be cancelled",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               Timer_Operation op;

               auto token = SingleshotTimer::start(cb, 100ms, op.callback());

               result.test_is_true("token is valid", token);
               result.test_is_true("token is armed", token.armed());

               cb->set_clock_forward(10ms);
               cb->get_next_scheduled_operation()();
               result.test_u64_eq(
                  "remaining time after the premature invocation", token.remaining(*cb).value_or(-1ms).count(), 90);

               token.cancel();
               result.test_is_false("token is no longer valid", token);
               result.test_is_false("token is no longer armed", token.armed());
               result.test_is_false("no remaining time after cancellation", token.remaining(*cb).has_value());

               cb->advance(100ms);
               result.test_is_false("deferred operation did not run", op);
            }),

      CHECK("deferred operation is cancelled when token is destroyed",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               Timer_Operation op;

               {
                  auto token = SingleshotTimer::start(cb, 100ms, op.callback());

                  result.test_is_true("token is valid", token);
                  result.test_is_true("token is armed", token.armed());

                  cb->set_clock_forward(10ms);
                  cb->get_next_scheduled_operation()();
               }

               cb->advance(100ms);
               result.test_is_false("deferred operation did not run", op);
            }),
   };
}

std::vector<Test::Result> retransmission_timer() {
   return {
      CHECK("retransmission timer is not armed on construction",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               Timer_Operation op;

               RetransmissionTimer timer(Retransmission_Test_Policy(100ms, 250ms, 500ms, 3), cb);

               result.test_is_false("retransmission timer is not armed", timer.retransmissions_armed());
               result.test_is_false("flight timer is not armed", timer.flight_timeout_armed());
               result.test_is_false("no next timeout on construction", timer.next_timeout().has_value());

               cb->advance(1000ms);
               result.test_is_false("deferred operation did not run", op);
            }),

      CHECK("cancelling a retransmission timer that does not run has no effect",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               Timer_Operation op;

               RetransmissionTimer timer(Retransmission_Test_Policy(100ms, 250ms, {}, 3), cb);

               result.test_is_false("timer is not armed", timer.retransmissions_armed());

               timer.cancel();
               result.test_is_false("timer is still not armed", timer.retransmissions_armed());

               cb->advance(1000ms);
               result.test_is_false("deferred operation did not run", op);
            }),

      CHECK(
         "starting a retransmission timer emits the deferred operation after the first timeout",
         [&](Test::Result& result) {
            auto cb = std::make_shared<Timer_Callbacks>();
            Timer_Operation op;

            RetransmissionTimer timer(Retransmission_Test_Policy(100ms, 250ms, 500ms, 3), cb);

            timer.start(op.callback());
            result.test_is_true("retransmission timer is armed", timer.retransmissions_armed());
            result.test_is_true("flight timer is armed", timer.flight_timeout_armed());
            result.test_u64_eq(
               "next timeout is the initial retransmission timeout", timer.next_timeout().value_or(-1ms).count(), 100);

            result.test_is_false("did not run yet", op);
            cb->advance(99ms);
            result.test_is_false("still didn't run yet", op);
            cb->advance(1ms);
            result.test_u32_eq("deferred operation ran once", op, 1);

            result.test_is_true("retransmission timer re-armed for retransmission", timer.retransmissions_armed());
            result.test_is_true("flight timer was not reset by the retransmission", timer.flight_timeout_armed());
            result.test_u64_eq(
               "next timeout is the doubled retransmission timeout", timer.next_timeout().value_or(-1ms).count(), 200);
         }),

      CHECK("retransmission timer re-emits with exponential backoff up to the maximum timeout",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               Timer_Operation op;

               RetransmissionTimer timer(Retransmission_Test_Policy(100ms, 250ms, {}, {}), cb);

               timer.start(op.callback());
               result.test_is_true("timer is armed", timer.retransmissions_armed());
               result.test_is_false("flight timer is not armed", timer.flight_timeout_armed());

               cb->advance(100ms);
               result.test_u32_eq("first retransmission ran", op, 1);

               cb->set_clock_forward(50ms);
               const auto early_retransmit = cb->get_next_scheduled_operation();
               result.test_no_throw("early retransmission timer invocation", [&] { early_retransmit(); });
               result.test_u32_eq("early invocation did not retransmit", op, 1);
               result.test_is_true("timer still armed after early invocation", timer.retransmissions_armed());
               result.test_u64_eq(
                  "next timeout still targets the original deadline", timer.next_timeout().value_or(-1ms).count(), 150);

               // timeout doubled: 100ms -> 200ms
               cb->advance(149ms);
               result.test_u32_eq("did not retransmit before the doubled timeout", op, 1);
               cb->advance(1ms);
               result.test_u32_eq("second retransmission ran", op, 2);

               // timeout doubled again but capped: 400ms -> 250ms
               cb->advance(249ms);
               result.test_u32_eq("did not retransmit before the capped timeout", op, 2);
               cb->advance(1ms);
               result.test_u32_eq("third retransmission ran", op, 3);

               // timeout stays capped at 250ms
               cb->advance(249ms);
               result.test_u32_eq("did not retransmit before the capped timeout", op, 3);
               cb->advance(1ms);
               result.test_u32_eq("fourth retransmission ran", op, 4);

               // with no maximum retransmission count configured, the timer
               // retransmits indefinitely at the capped timeout and never gives up
               result.test_no_throw("timer never times out", [&] {
                  for(uint32_t i = 5; i <= 20; ++i) {
                     cb->advance(249ms);
                     result.test_u32_eq("did not retransmit before the capped timeout", op, i - 1);
                     cb->advance(1ms);
                     result.test_u32_eq("retransmission ran at the capped timeout", op, i);
                  }
               });

               result.test_is_true("timer is still armed", timer.retransmissions_armed());
            }),

      CHECK("retransmission timer eventually times out with an exception",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               Timer_Operation op;

               RetransmissionTimer timer(Retransmission_Test_Policy(100ms, 250ms, {}, 2), cb);

               timer.start(op.callback());
               result.test_is_true("timer is armed", timer.retransmissions_armed());
               result.test_is_false("flight timer is not armed", timer.flight_timeout_armed());

               cb->advance(100ms);
               result.test_u32_eq("first retransmission ran", op, 1);
               cb->advance(200ms);
               result.test_u32_eq("second retransmission ran", op, 2);

               const auto early_final_timeout = cb->get_next_scheduled_operation();
               result.test_no_throw("early final timeout invocations do not exhaust budget", [&] {
                  early_final_timeout();
                  early_final_timeout();
                  early_final_timeout();
               });
               result.test_u32_eq("early invocations did not retransmit", op, 2);

               // The timer expires and throws even though no timeout handler
               // was set.
               result.test_throws<TLS_Exception>(
                  "timer gave up after the maximum number of retransmissions",
                  "DTLS (post-)handshake message exchange timed out: maximum retransmissions exceeded",
                  [&] { cb->advance(250ms); });
               result.test_u32_eq("no further retransmission was emitted", op, 2);
               result.test_is_false("timer is no longer armed after giving up", timer.retransmissions_armed());
               result.test_is_false("no next timeout after giving up", timer.next_timeout().has_value());

               // A new flight can still be sent after the previous one timed
               // out. The timeout handler set here persists across restarts and
               // is only invoked when the retransmission budget is exhausted.
               Timer_Operation timeout_op;
               timer.set_timeout_handler(timeout_op.callback());
               timer.start(op.callback());
               result.test_is_true("timer is armed after restart", timer.retransmissions_armed());
               result.test_u32_eq("timeout handler not called while the timer is armed", timeout_op, 0);

               cb->advance(99ms);
               result.test_u32_eq("did not retransmit before the initial timeout", op, 2);
               result.test_u32_eq("timeout handler not called before the retransmission", timeout_op, 0);
               cb->advance(1ms);
               result.test_u32_eq("retransmission ran after the initial timeout", op, 3);
               result.test_u32_eq("timeout handler not called on the retransmission", timeout_op, 0);

               cb->advance(200ms);
               result.test_u32_eq("second retransmission ran", op, 4);
               result.test_u32_eq("timeout handler not called on retransmissions", timeout_op, 0);

               result.test_throws<TLS_Exception>(
                  "timer gave up again after the maximum number of retransmissions",
                  "DTLS (post-)handshake message exchange timed out: maximum retransmissions exceeded",
                  [&] { cb->advance(250ms); });
               result.test_u32_eq("timeout handler was called when the timer expired", timeout_op, 1);
               result.test_u32_eq("no further retransmission was emitted", op, 4);
               result.test_is_false("timer is no longer armed after giving up again", timer.retransmissions_armed());
            }),

      CHECK("restarting a retransmission timer resets the exponential backoff and replaces the operation",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               Timer_Operation op;
               Timer_Operation restarted_op;

               RetransmissionTimer timer(Retransmission_Test_Policy(100ms, 250ms, {}, {}), cb);

               timer.start(op.callback());
               cb->advance(100ms);
               cb->advance(200ms);
               result.test_u32_eq("two retransmissions ran", op, 2);
               result.test_is_true("timer is armed", timer.retransmissions_armed());

               // restart (with a new operation) while the backed-off timer (250ms) is still pending
               timer.start(restarted_op.callback());
               result.test_is_true("timer is armed after restart", timer.retransmissions_armed());

               cb->advance(99ms);
               result.test_u32_eq("did not retransmit before the initial timeout", restarted_op, 0);
               cb->advance(1ms);
               result.test_u32_eq("retransmission ran after the reset initial timeout", restarted_op, 1);

               // backoff starts over: 100ms -> 200ms
               cb->advance(199ms);
               result.test_u32_eq("did not retransmit before the doubled timeout", restarted_op, 1);
               cb->advance(1ms);
               result.test_u32_eq("retransmission ran after the reset doubled timeout", restarted_op, 2);

               result.test_u32_eq("previous operation was never invoked again", op, 2);
               result.test_is_true("timer is still armed", timer.retransmissions_armed());
            }),

      CHECK("destroying a running retransmission timer stops further retransmissions",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               Timer_Operation op;
               Timer_Operation timeout_op;

               {
                  RetransmissionTimer timer(Retransmission_Test_Policy(100ms, 250ms, 500ms, {}), cb);

                  timer.start(op.callback());
                  timer.set_timeout_handler(timeout_op.callback());
                  result.test_is_true("retransmission timer is armed", timer.retransmissions_armed());
                  result.test_is_true("flight timer is armed", timer.flight_timeout_armed());

                  cb->advance(100ms);
                  result.test_u32_eq("first retransmission ran", op, 1);
                  result.test_is_true("retransmission timer is still armed", timer.retransmissions_armed());
                  result.test_u64_eq(
                     "next timeout before the timer is destroyed", timer.next_timeout().value_or(-1ms).count(), 200);
                  result.test_u32_eq("timeout handler not called while the timer is armed", timeout_op, 0);
               }

               result.test_no_throw("neither timer fires after the timer was destroyed", [&] { cb->advance(1000ms); });
               result.test_u32_eq("no further retransmissions ran", op, 1);
               result.test_u32_eq("timeout handler not called after the timer was destroyed", timeout_op, 0);
            }),

      CHECK("cancelling a running retransmission timer stops further retransmissions",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               Timer_Operation op;
               Timer_Operation timeout_op;

               RetransmissionTimer timer(Retransmission_Test_Policy(100ms, 250ms, {}, {}), cb);

               timer.start(op.callback());
               timer.set_timeout_handler(timeout_op.callback());
               result.test_is_true("timer is armed", timer.retransmissions_armed());

               cb->advance(100ms);
               result.test_u32_eq("first retransmission ran", op, 1);
               result.test_is_true("timer is still armed", timer.retransmissions_armed());
               result.test_u32_eq("timeout handler not called while the timer is armed", timeout_op, 0);

               timer.stop_retransmissions();
               result.test_is_false("timer is no longer armed", timer.retransmissions_armed());
               result.test_is_false("no next timeout after stopping the retransmissions",
                                    timer.next_timeout().has_value());

               cb->advance(1000ms);
               result.test_u32_eq("no further retransmissions ran", op, 1);
               result.test_u32_eq("timeout handler not called after cancellation", timeout_op, 0);

               // restarting after a cancel starts with the initial timeout again
               timer.start(op.callback());
               result.test_is_true("timer is armed after restart", timer.retransmissions_armed());

               cb->advance(99ms);
               result.test_u32_eq("did not retransmit before the initial timeout", op, 1);
               cb->advance(1ms);
               result.test_u32_eq("retransmission ran after the initial timeout", op, 2);
               result.test_u32_eq("timeout handler still not called after the restart", timeout_op, 0);
            }),

      CHECK("retransmission budget is exhausted before the flight timeout is reached",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               Timer_Operation op;
               Timer_Operation timeout_op;

               // Retransmission schedule: 100ms, 200ms, 250ms, 250ms (capped).
               // The retransmission budget of 3 is exhausted after 800ms, well
               // before the flight timeout of 1000ms is reached.
               RetransmissionTimer timer(Retransmission_Test_Policy(100ms, 250ms, 1000ms, 3), cb);

               timer.start(op.callback());
               timer.set_timeout_handler(timeout_op.callback());
               result.test_is_true("retransmission timer is armed", timer.retransmissions_armed());
               result.test_is_true("flight timer is armed", timer.flight_timeout_armed());

               cb->advance(100ms);
               result.test_u32_eq("first retransmission ran", op, 1);
               cb->advance(200ms);
               result.test_u32_eq("second retransmission ran", op, 2);
               cb->advance(250ms);
               result.test_u32_eq("third retransmission ran", op, 3);
               result.test_is_true("retransmission timer is still armed", timer.retransmissions_armed());
               result.test_is_true("flight timer is still armed", timer.flight_timeout_armed());
               result.test_u64_eq("next timeout is the remaining retransmission timeout",
                                  timer.next_timeout().value_or(-1ms).count(),
                                  250);
               result.test_u32_eq("timeout handler not called on retransmissions", timeout_op, 0);

               result.test_throws<TLS_Exception>(
                  "timer gave up when the retransmission budget was exhausted",
                  "DTLS (post-)handshake message exchange timed out: maximum retransmissions exceeded",
                  [&] { cb->advance(250ms); });
               result.test_u32_eq("timeout handler was called when the timer expired", timeout_op, 1);
               result.test_u32_eq("no further retransmission was emitted", op, 3);
               result.test_is_false("retransmission timer is no longer armed", timer.retransmissions_armed());
               result.test_is_false("flight timer was cancelled when the budget was exhausted",
                                    timer.flight_timeout_armed());
               result.test_is_false("no next timeout after the budget was exhausted", timer.next_timeout().has_value());

               // The flight timeout deadline is reached right now. It must not
               // fire anymore because the timer already gave up.
               result.test_no_throw("flight timer does not fire after the budget was exhausted",
                                    [&] { cb->advance(200ms); });
               result.test_u32_eq("no further retransmission was emitted after giving up", op, 3);
               result.test_u32_eq("timeout handler was called only once", timeout_op, 1);
            }),

      CHECK("flight timeout fires while retransmissions are still ongoing",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               Timer_Operation op;
               Timer_Operation timeout_op;

               // Retransmission schedule: 100ms, 200ms, 250ms, ... The flight
               // timeout of 350ms strikes between the second and third
               // retransmission, long before the retransmission budget of 5 is
               // exhausted.
               RetransmissionTimer timer(Retransmission_Test_Policy(100ms, 250ms, 350ms, 5), cb);

               timer.start(op.callback());
               timer.set_timeout_handler(timeout_op.callback());

               cb->advance(100ms);
               result.test_u32_eq("first retransmission ran", op, 1);
               cb->advance(200ms);
               result.test_u32_eq("second retransmission ran", op, 2);

               // The retransmissions did not push the flight timer's deadline.
               result.test_is_true("flight timer is still armed", timer.flight_timeout_armed());
               result.test_is_true("retransmission timer is still armed", timer.retransmissions_armed());
               result.test_u64_eq(
                  "next timeout is the earlier flight timeout", timer.next_timeout().value_or(-1ms).count(), 50);

               cb->advance(49ms);
               result.test_u32_eq("did not retransmit before the flight timeout", op, 2);
               result.test_u32_eq("timeout handler not called before the flight timeout", timeout_op, 0);

               result.test_throws<TLS_Exception>(
                  "timer gave up when the flight timeout was reached",
                  "DTLS (post-)handshake message exchange timed out: flight timeout exceeded",
                  [&] { cb->advance(1ms); });
               result.test_u32_eq("timeout handler was called when the flight timeout was reached", timeout_op, 1);
               result.test_u32_eq("no further retransmission was emitted", op, 2);
               result.test_is_false("retransmission timer was cancelled by the flight timeout",
                                    timer.retransmissions_armed());
               result.test_is_false("flight timer is no longer armed", timer.flight_timeout_armed());
               result.test_is_false("no next timeout after the flight timeout", timer.next_timeout().has_value());

               result.test_no_throw("no further timer activity after the flight timeout", [&] { cb->advance(1000ms); });
               result.test_u32_eq("no further retransmission was emitted after the flight timeout", op, 2);
               result.test_u32_eq("timeout handler was called only once", timeout_op, 1);
            }),

      CHECK("flight timeout fires before the first retransmission",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               Timer_Operation op;
               Timer_Operation timeout_op;

               // The flight timeout of 50ms is shorter than the initial
               // retransmission timeout of 100ms.
               RetransmissionTimer timer(Retransmission_Test_Policy(100ms, 250ms, 50ms, 3), cb);

               timer.start(op.callback());
               timer.set_timeout_handler(timeout_op.callback());
               result.test_is_true("retransmission timer is armed", timer.retransmissions_armed());
               result.test_is_true("flight timer is armed", timer.flight_timeout_armed());

               // Prematurely invoking the flight timer's operation re-arms it
               // for the remaining time instead of firing it.
               cb->set_clock_forward(10ms);
               const auto premature_flight_timeout = cb->get_next_scheduled_operation();
               result.test_no_throw("premature flight timeout invocation", [&] { premature_flight_timeout(); });
               result.test_u32_eq("premature invocation did not give up", op, 0);
               result.test_u32_eq("premature invocation did not call the timeout handler", timeout_op, 0);
               result.test_is_true("flight timer is still armed after premature invocation",
                                   timer.flight_timeout_armed());
               result.test_is_true("retransmission timer is still armed after premature invocation",
                                   timer.retransmissions_armed());
               result.test_u64_eq("next timeout still targets the original flight deadline",
                                  timer.next_timeout().value_or(-1ms).count(),
                                  40);
               const auto op_count_after_premature = cb->deferred_op_count();
               premature_flight_timeout();
               result.test_sz_eq("duplicate premature invocation did not schedule again",
                                 cb->deferred_op_count(),
                                 op_count_after_premature);

               cb->advance(39ms);
               result.test_u32_eq("did not give up before the flight timeout", op, 0);

               result.test_throws<TLS_Exception>(
                  "flight timeout fired at the originally scheduled deadline",
                  "DTLS (post-)handshake message exchange timed out: flight timeout exceeded",
                  [&] { cb->advance(1ms); });
               result.test_u32_eq("timeout handler was called when the flight timeout was reached", timeout_op, 1);
               result.test_u32_eq("no retransmission was emitted at all", op, 0);
               result.test_is_false("retransmission timer was cancelled by the flight timeout",
                                    timer.retransmissions_armed());
               result.test_is_false("flight timer is no longer armed", timer.flight_timeout_armed());

               result.test_no_throw("no further timer activity after the flight timeout", [&] { cb->advance(1000ms); });
            }),

      CHECK("without a retransmission limit, the flight timeout bounds the patience",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               Timer_Operation op;
               Timer_Operation timeout_op;

               // Retransmission schedule: 100ms, 200ms, 250ms, 250ms, ... The
               // flight timeout of 450ms strikes between the second and third
               // retransmission. Without a retransmission limit, the flight
               // timer is the only bound on the exchange's patience.
               RetransmissionTimer timer(Retransmission_Test_Policy(100ms, 250ms, 450ms, {}), cb);

               timer.start(op.callback());
               timer.set_timeout_handler(timeout_op.callback());

               cb->advance(100ms);
               result.test_u32_eq("first retransmission ran", op, 1);
               cb->advance(200ms);
               result.test_u32_eq("second retransmission ran", op, 2);
               result.test_is_true("retransmission timer is still armed", timer.retransmissions_armed());
               result.test_is_true("flight timer is still armed", timer.flight_timeout_armed());

               cb->advance(149ms);
               result.test_u32_eq("did not retransmit before the flight timeout", op, 2);
               result.test_u64_eq(
                  "one millisecond before the flight timeout", timer.next_timeout().value_or(-1ms).count(), 1);

               result.test_throws<TLS_Exception>(
                  "timer gave up when the flight timeout was reached",
                  "DTLS (post-)handshake message exchange timed out: flight timeout exceeded",
                  [&] { cb->advance(1ms); });
               result.test_u32_eq("timeout handler was called when the flight timeout was reached", timeout_op, 1);
               result.test_u32_eq("no further retransmission was emitted", op, 2);
               result.test_is_false("retransmission timer was cancelled by the flight timeout",
                                    timer.retransmissions_armed());
               result.test_is_false("flight timer is no longer armed", timer.flight_timeout_armed());

               result.test_no_throw("no further timer activity after the flight timeout", [&] { cb->advance(1000ms); });
               result.test_u32_eq("no further retransmission was emitted after the flight timeout", op, 2);
            }),

      CHECK("stopping retransmissions does not affect the flight timer",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               Timer_Operation op;
               Timer_Operation timeout_op;

               RetransmissionTimer timer(Retransmission_Test_Policy(100ms, 250ms, 350ms, 3), cb);

               timer.start(op.callback());
               timer.set_timeout_handler(timeout_op.callback());
               result.test_is_true("flight timer is armed", timer.flight_timeout_armed());

               cb->advance(100ms);
               result.test_u32_eq("first retransmission ran", op, 1);

               timer.stop_retransmissions();
               result.test_is_false("retransmission timer is no longer armed", timer.retransmissions_armed());
               result.test_is_true("flight timer is still armed", timer.flight_timeout_armed());
               result.test_u64_eq(
                  "next timeout is the remaining flight timeout", timer.next_timeout().value_or(-1ms).count(), 250);

               // The cancelled retransmission timer does not fire anymore.
               result.test_no_throw("cancelled retransmission timer does not fire", [&] { cb->advance(200ms); });
               result.test_u32_eq("no retransmission after stopping", op, 1);
               result.test_u32_eq("timeout handler not called by the cancelled retransmission timer", timeout_op, 0);

               // The flight timer fires 350ms after the flight was sent, not
               // 350ms after the retransmissions were stopped.
               cb->advance(49ms);
               result.test_u32_eq("did not give up before the flight timeout", op, 1);
               result.test_u64_eq(
                  "one millisecond before the flight timeout", timer.next_timeout().value_or(-1ms).count(), 1);
               result.test_throws<TLS_Exception>(
                  "flight timeout fired at the deadline of the original flight",
                  "DTLS (post-)handshake message exchange timed out: flight timeout exceeded",
                  [&] { cb->advance(1ms); });
               result.test_u32_eq("timeout handler was called when the flight timeout was reached", timeout_op, 1);
               result.test_is_false("retransmission timer is no longer armed", timer.retransmissions_armed());
               result.test_is_false("flight timer is no longer armed", timer.flight_timeout_armed());

               result.test_no_throw("no further timer activity after the flight timeout", [&] { cb->advance(1000ms); });
            }),

      CHECK("restarting the timer re-arms the flight timer with a fresh budget",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               Timer_Operation op;
               Timer_Operation restarted_op;
               Timer_Operation timeout_op;

               RetransmissionTimer timer(Retransmission_Test_Policy(100ms, 250ms, 280ms, {}), cb);

               timer.start(op.callback());
               timer.set_timeout_handler(timeout_op.callback());

               cb->advance(100ms);
               result.test_u32_eq("first retransmission ran", op, 1);

               timer.stop_retransmissions();
               result.test_is_true("flight timer is still armed", timer.flight_timeout_armed());

               // Restarting while the previous flight timer is still armed
               // replaces it with a fresh budget instead of extending it.
               cb->advance(150ms);
               timer.start(restarted_op.callback());
               result.test_is_true("retransmission timer is armed after the restart", timer.retransmissions_armed());
               result.test_is_true("flight timer is armed after the restart", timer.flight_timeout_armed());
               result.test_u64_eq("next timeout is the restart's initial retransmission timeout",
                                  timer.next_timeout().value_or(-1ms).count(),
                                  100);

               // The previous flight timer's deadline (280ms after the first
               // start) passes without firing.
               cb->advance(50ms);
               result.test_u32_eq("previous flight timer's deadline passed without firing", timeout_op, 0);
               result.test_u32_eq("restarted operation did not run yet", restarted_op, 0);

               cb->advance(50ms);
               result.test_u32_eq("retransmission ran after the restart's initial timeout", restarted_op, 1);
               result.test_u32_eq("previous operation was never invoked again", op, 1);
               result.test_is_true("flight timer is still armed", timer.flight_timeout_armed());
               result.test_u64_eq(
                  "next timeout is the restarted flight timeout", timer.next_timeout().value_or(-1ms).count(), 180);

               // The new flight timer fires 280ms after the restart, not 280ms
               // after the original start.
               cb->advance(179ms);
               result.test_u32_eq("did not give up before the restarted flight timeout", restarted_op, 1);
               result.test_throws<TLS_Exception>(
                  "flight timeout fired at the deadline of the restarted flight",
                  "DTLS (post-)handshake message exchange timed out: flight timeout exceeded",
                  [&] { cb->advance(1ms); });
               result.test_u32_eq("timeout handler was called when the flight timeout was reached", timeout_op, 1);
               result.test_u32_eq("no further retransmission was emitted", restarted_op, 1);
               result.test_is_false("retransmission timer is no longer armed", timer.retransmissions_armed());
               result.test_is_false("flight timer is no longer armed", timer.flight_timeout_armed());

               result.test_no_throw("no further timer activity after the flight timeout", [&] { cb->advance(1000ms); });
            }),

      CHECK("cancelling the timer disarms both the retransmission and the flight timer",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               Timer_Operation op;
               Timer_Operation timeout_op;

               RetransmissionTimer timer(Retransmission_Test_Policy(100ms, 250ms, 300ms, {}), cb);

               timer.start(op.callback());
               timer.set_timeout_handler(timeout_op.callback());
               result.test_is_true("retransmission timer is armed", timer.retransmissions_armed());
               result.test_is_true("flight timer is armed", timer.flight_timeout_armed());

               cb->advance(100ms);
               result.test_u32_eq("first retransmission ran", op, 1);

               timer.cancel();
               result.test_is_false("retransmission timer is no longer armed", timer.retransmissions_armed());
               result.test_is_false("flight timer is no longer armed", timer.flight_timeout_armed());
               result.test_is_false("no next timeout after the cancellation", timer.next_timeout().has_value());

               result.test_no_throw("neither timer fires after the timer was cancelled", [&] { cb->advance(1000ms); });
               result.test_u32_eq("no further retransmission was emitted", op, 1);
               result.test_u32_eq("timeout handler not called after cancellation", timeout_op, 0);
            }),

      CHECK("cancelling after stopping the retransmissions also disarms the flight timer",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               Timer_Operation op;
               Timer_Operation timeout_op;

               RetransmissionTimer timer(Retransmission_Test_Policy(100ms, 250ms, 300ms, {}), cb);

               timer.start(op.callback());
               timer.set_timeout_handler(timeout_op.callback());

               cb->advance(100ms);
               result.test_u32_eq("first retransmission ran", op, 1);

               timer.stop_retransmissions();
               result.test_is_false("retransmission timer is no longer armed", timer.retransmissions_armed());
               result.test_is_true("flight timer is still armed", timer.flight_timeout_armed());
               result.test_u64_eq(
                  "next timeout is the remaining flight timeout", timer.next_timeout().value_or(-1ms).count(), 200);

               timer.cancel();
               result.test_is_false("flight timer is no longer armed after the cancellation",
                                    timer.flight_timeout_armed());
               result.test_is_false("no next timeout after the cancellation", timer.next_timeout().has_value());

               result.test_no_throw("neither timer fires after the timer was cancelled", [&] { cb->advance(1000ms); });
               result.test_u32_eq("no further retransmission was emitted", op, 1);
               result.test_u32_eq("timeout handler not called after cancellation", timeout_op, 0);
            }),
   };
}

}  // namespace

BOTAN_REGISTER_TEST_FN("tls", "dtls_timers", singleshot_timer, retransmission_timer);

}  // namespace Botan_Tests

#endif
