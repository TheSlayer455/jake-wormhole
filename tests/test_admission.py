"""Labeled synthetic capacity and real disposable Linux process/lock fixtures."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from wormhole import admission as a
from wormhole.runs import RunError, read_json

SOURCE = Path(__file__).resolve().parents[1]
SHA = "a" * 40


def observed():
    return {"schema_version": "1.0", "synthetic": True, "observed_at": a.now(),
        "boot_id": "12345678-1234-4234-9234-123456789abc", "memory_total_bytes": 32 * 1024 * a.MIB,
        "memory_available_bytes": 24 * 1024 * a.MIB, "runtime_disk_free_bytes": 100 * 1024 * a.MIB,
        "docker_disk_free_bytes": 100 * 1024 * a.MIB, "cpu_count": 16, "load1": 1,
        "docker": {"server_version": "29.6.0", "cgroup_version": "2", "cgroup_driver": "systemd",
            "controllers": ["cpu", "memory", "pids"], "memory_limit": True, "swap_limit": True,
            "cpu_quota": True, "pids_limit": True},
        "workloads": {"running_count": 7, "cpu_cores": 0.75, "memory_bytes": 2 * 1024 * a.MIB}}


class Planning(unittest.TestCase):
    def test_profiles_account_all_services_and_keep_count_separate_from_concurrency(self):
        for name, count, concurrency in (("smoke", 1, 1), ("five-targets", 5, 2), ("twenty-targets", 20, 4)):
            plan = a.build_plan(name, observed())
            self.assertTrue(plan["admitted"])
            self.assertEqual(plan["target_count"], count)
            self.assertEqual(plan["controller_concurrency"], concurrency)
            self.assertEqual(plan["build_concurrency"], 1)
            self.assertEqual(plan["requirements"]["runtime_memory_bytes"], (count * 256 + 512 * 3) * a.MIB)
            self.assertEqual(plan["requirements"]["build_memory_bytes"], 3072 * a.MIB)
            self.assertFalse(plan["builds_overlap_target_execution"])
            self.assertFalse(plan["limits_enforced"])
            self.assertFalse(plan["allocation_performed"])
            self.assertTrue(plan["synthetic"])
            self.assertFalse(plan["production_iso_eligible"])
            self.assertFalse(plan["materialization"]["daemon_operation_cgroup_capped"])
            self.assertGreater(plan["materialization"]["extra_disk_reserve_bytes"], 0)
            self.assertEqual(plan["limits"]["provisioner"]["disk_mib"], 512)

    def test_exact_thresholds_and_independent_smaller_profile_after_refusal(self):
        value = observed()
        plan = a.build_plan("twenty-targets", value)
        needed = plan["requirements"]["peak_memory_bytes"] + 4096 * a.MIB
        value["memory_available_bytes"] = needed
        self.assertTrue(a.build_plan("twenty-targets", value)["admitted"])
        value["memory_available_bytes"] -= 1
        refusal = a.build_plan("twenty-targets", value)
        self.assertFalse(refusal["admitted"])
        self.assertIn("host_memory_headroom", refusal["refusal_reasons"])
        self.assertFalse(refusal["allocation_performed"])
        self.assertTrue(a.build_plan("smoke", value)["admitted"])
        value = observed()
        value["docker_disk_free_bytes"] = plan["requirements"]["disk_bytes"] + 4096 * a.MIB - 1
        self.assertIn("host_disk_headroom", a.build_plan("twenty-targets", value)["refusal_reasons"])
        value = observed()
        value["workloads"]["cpu_cores"] = 15
        self.assertIn("host_cpu_headroom", a.build_plan("smoke", value)["refusal_reasons"])

    def test_incomplete_stale_nonfinite_or_unsupported_observations_fail_closed(self):
        for key in observed():
            value = observed()
            del value[key]
            with self.subTest(missing=key), self.assertRaises((a.AdmissionError, RunError)):
                a.build_plan("smoke", value)
        for key, bad in (("memory_available_bytes", True), ("load1", float("nan")),
                         ("cpu_count", 0), ("memory_total_bytes", 2**10000)):
            value = observed()
            value[key] = bad
            with self.subTest(field=key), self.assertRaises(a.AdmissionError):
                a.build_plan("smoke", value)
        for key, bad in (("cpu_quota", None), ("pids_limit", False), ("controllers", ["cpu", "memory"]), ("cgroup_version", "1")):
            value = observed()
            value["docker"][key] = bad
            with self.subTest(docker_field=key), self.assertRaises(a.AdmissionError):
                a.build_plan("smoke", value)
        value = observed()
        value["observed_at"] = (datetime.now(timezone.utc) - timedelta(seconds=31)).isoformat().replace("+00:00", "Z")
        with self.assertRaises(a.AdmissionError):
            a.build_plan("smoke", value)

    def test_profile_edits_bool_aliases_and_unsafe_names_are_not_silent_overrides(self):
        for name in ("../smoke", "arbitrary", None):
            with self.subTest(name=name), self.assertRaises(a.AdmissionError):
                a.load_profile(name)
        profile = a.load_profile("smoke")
        profile["target_count"] = True
        with self.assertRaises(a.AdmissionError):
            a.build_plan(profile, observed())
        profile = a.load_profile("twenty-targets")
        profile["limits"]["target"]["memory_mib"] = 1
        with self.assertRaises(a.AdmissionError):
            a.build_plan(profile, observed())

    def test_generated_docker_and_terraform_limits_keep_pid_gap_explicit(self):
        plan = a.build_plan("smoke", observed())
        for limits in plan["limits"].values():
            docker, terraform = limits["docker_create"], limits["terraform"]
            self.assertEqual(docker["memory_bytes"], limits["memory_mib"] * a.MIB)
            self.assertEqual(docker["memory_swap_bytes"], docker["memory_bytes"])
            self.assertEqual(docker["nano_cpus"], round(limits["cpus"] * 10**9))
            self.assertGreater(docker["pids_limit"], 0)
            self.assertEqual(docker["cap_drop"], ["ALL"])
            self.assertTrue(docker["read_only"])
            self.assertTrue(docker["no_new_privileges"])
            self.assertFalse(terraform["start"])
            self.assertFalse(terraform["must_run"])
            self.assertNotIn("pids_limit", terraform)
            self.assertNotIn("pid_mode", terraform)
            self.assertTrue(limits["require_stopped_before_pid_enforcement"])
            self.assertTrue(all(type(x) is str for x in terraform["log_opts"].values()))

    def test_readonly_commands_use_fixed_local_socket_and_bound_output(self):
        with patch.object(a, "_run_process", return_value={"status": "pass", "log_truncated": False, "log": b"synthetic"}) as process:
            self.assertEqual(a._read_command(("docker", "--host", "unix:///var/run/docker.sock", "ps"), "/tmp"), "synthetic")
            self.assertEqual(process.call_args.kwargs["timeout"], 5)
        with patch.object(a, "_run_process", return_value={"status": "pass", "log_truncated": True, "log": b"synthetic-sensitive-do-not-echo"}):
            with self.assertRaises(a.AdmissionError) as error:
                a._read_command(("docker", "ps"), "/tmp")
            self.assertNotIn("sensitive", str(error.exception))
        self.assertEqual(a._memory_size("1.5GiB"), round(1.5 * 1024**3))
        self.assertEqual(a._memory_size("0B"), 0)
        with self.assertRaises(a.AdmissionError):
            a._memory_size("not measured")

    def test_real_admission_root_is_pinned_before_creating_any_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "operator-selected-second-lock"
            with self.assertRaises(a.AdmissionError) as error:
                a.AdmissionLease(root, str(uuid4()), SHA)
            self.assertEqual(error.exception.code, "noncanonical_root")
            self.assertFalse(root.exists())

    def test_collector_parses_cpu_capabilities_and_whitelists_workload_measurements(self):
        with tempfile.TemporaryDirectory() as temporary:
            info = {"ServerVersion": "29.6.0", "DockerRootDir": temporary, "OSType": "linux", "NCPU": 16,
                "CgroupDriver": "systemd", "CgroupVersion": "2", "MemoryLimit": True, "SwapLimit": True,
                "CPUCfsQuota": True, "CPUCfsPeriod": True, "PidsLimit": True,
                "UnselectedMetadata": "synthetic-sensitive-never-export"}
            paths = {Path("/proc/meminfo"): "MemTotal:       33554432 kB\nMemAvailable:   25165824 kB\n",
                     Path("/proc/sys/kernel/random/boot_id"): observed()["boot_id"],
                     Path("/sys/fs/cgroup/cgroup.controllers"): "cpu memory pids io"}
            commands = []
            def command(arguments, cwd):
                commands.append(arguments)
                if "info" in arguments:
                    return json.dumps(info)
                if "ps" in arguments:
                    return "a" * 64 + "\n"
                return json.dumps({"id": "a" * 64, "cpu": "25.00%", "memory": "1.5GiB / 2GiB"})
            with patch.object(a.sys, "platform", "linux"), patch.object(a, "_read_command", side_effect=command), \
                 patch.object(Path, "read_text", lambda path, *args, **kwargs: paths[path]), \
                 patch.object(a.os, "sched_getaffinity", return_value=set(range(16)), create=True), \
                 patch.object(a.os, "getloadavg", return_value=(1, 1, 1), create=True), \
                 patch.object(a.shutil, "disk_usage", return_value=type("Usage", (), {"free": 100 * 1024 * a.MIB})()):
                result = a.collect_observations(temporary)
                self.assertFalse(result["synthetic"])
                self.assertTrue(result["docker"]["cpu_quota"])
                self.assertEqual(result["workloads"]["cpu_cores"], 0.25)
                self.assertEqual(result["workloads"]["memory_bytes"], round(1.5 * 1024**3))
                self.assertNotIn("sensitive", json.dumps(result))
                self.assertTrue(all(tuple(args[:3]) == ("docker", "--host", "unix:///var/run/docker.sock") for args in commands))
                info["CPUCfsQuota"] = None
                with self.assertRaises(a.AdmissionError):
                    a.collect_observations(temporary)


@unittest.skipUnless(sys.platform.startswith("linux"), "Real shared flock/process fixtures require Linux")
class Leases(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="wormhole-admission-fixture-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "infrastructure"

    def lease(self, identifier=None, **kwargs):
        return a.AdmissionLease(self.root, identifier or str(uuid4()), SHA,
                                collector=lambda _: observed(), allow_synthetic=True, **kwargs)

    def resume(self, identifier, **kwargs):
        return a.AdmissionLease.resume(self.root, identifier, SHA, allow_synthetic=True, **kwargs)

    def child(self, code, *args, cwd=None):
        prefix = "import sys; sys.path.insert(0," + repr(str(SOURCE)) + "); "
        return subprocess.Popen([sys.executable, "-B", "-u", "-c", prefix + code, *map(str, args)],
                                cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def test_lock_inode_stable_and_two_processes_cannot_share_slot(self):
        with self.lease() as first:
            inode = (self.root / "infrastructure.lock").stat().st_ino
            code = "from wormhole.admission import AdmissionLease,AdmissionError; from uuid import uuid4;\ntry:\n with AdmissionLease(sys.argv[1],str(uuid4()),'a'*40,allow_synthetic=True): pass\nexcept AdmissionError as e: print(e.code)"
            elsewhere = Path(self.temporary.name) / "other-writer"
            elsewhere.mkdir()
            process = self.child(code, self.root, cwd=elsewhere)
            output, error = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, error)
            self.assertEqual(output.strip(), "infrastructure_busy")
            first.finish(reconciliation_complete=True)
        with self.lease() as second:
            self.assertEqual((self.root / "infrastructure.lock").stat().st_ino, inode)
            second.finish(reconciliation_complete=True)
        self.assertTrue((self.root / "infrastructure.lock").exists())

    def test_crash_releases_kernel_lock_but_durable_journal_blocks_new_admission(self):
        code = "import json,os; from wormhole.admission import AdmissionLease; from uuid import uuid4; fixture=json.loads(sys.argv[2]);\nwith AdmissionLease(sys.argv[1],str(uuid4()),'a'*40,collector=lambda _:fixture,allow_synthetic=True) as lease:\n lease.set_phase('assembling'); lease.register_resource('container','c'*64); os._exit(19)"
        process = self.child(code, self.root, json.dumps(observed()))
        output, error = process.communicate(timeout=5)
        self.assertEqual(process.returncode, 19, error)
        record = read_json(self.root / "admission.json")
        self.assertEqual(record["state"], "active")
        self.assertEqual(record["resources"][0]["id"], "c" * 64)
        self.assertEqual(record["resources"][0]["outcome"], "pending")
        with self.assertRaises(a.AdmissionError) as blocked:
            with self.lease():
                self.fail("Crash leftovers authorized duplicate allocation")
        self.assertEqual(blocked.exception.code, "unreconciled_run")
        with self.resume(record["run_id"]) as resumed:
            self.assertEqual(resumed.record["owner_pid"], process.pid)  # Original provenance survives resume.
            self.assertEqual(resumed.plan, record["plan"])
            resumed.set_phase("reconciling")
            # Synthetic adapter proof: the exact fixture ID was accounted for, not a Docker observation.
            resumed.reconcile_resource("container", "c" * 64)
            resumed.finish(reconciliation_complete=True)
        self.assertEqual(read_json(self.root / "admission.json")["state"], "finished")

    def test_cancellation_never_auto_completes_and_empty_allocation_intent_still_blocks(self):
        with self.assertRaises(KeyboardInterrupt):
            with self.lease() as lease:
                lease.set_phase("assembling")
                raise KeyboardInterrupt
        self.assertEqual(read_json(self.root / "admission.json")["state"], "active")
        with self.assertRaises(a.AdmissionError):
            with self.lease():
                pass

    def test_each_allocation_phase_refreshes_under_lock_and_refusal_keeps_resources(self):
        measurements = [observed(), observed(), observed()]
        measurements[-1]["memory_available_bytes"] = 1
        collector = iter(measurements)
        with a.AdmissionLease(self.root, str(uuid4()), SHA, collector=lambda _: next(collector), allow_synthetic=True) as lease:
            lease.set_phase("assembling")
            lease.register_resource("container", "e" * 64)
            with self.assertRaises(a.AdmissionError) as error:
                lease.set_phase("materializing")
            self.assertEqual(error.exception.code, "capacity_refused")
            self.assertEqual(read_json(self.root / "admission.json")["resources"][0]["outcome"], "pending")
            self.assertEqual(read_json(self.root / "admission.json")["phase"], "assembling")
            # Cleanup must remain possible without consuming another measurement.
            lease.set_phase("reconciling")
            lease.reconcile_resource("container", "e" * 64)
            lease.finish(reconciliation_complete=True)

    def test_phase_limits_require_reconciliation_and_allow_only_retained_images(self):
        with self.lease() as lease:
            with self.assertRaises(a.AdmissionError):
                lease.register_resource("container", "a" * 64)
            lease.set_phase("assembling")
            lease.register_resource("container", "a" * 64)
            with self.assertRaises(a.AdmissionError):
                lease.register_resource("container", "b" * 64)
            with self.assertRaises(a.AdmissionError):
                lease.set_phase("assembling")
            with self.assertRaises(a.AdmissionError):
                lease.set_phase("provisioning")
            lease.set_phase("materializing")
            lease.register_resource("image", "sha256:" + "b" * 64)
            with self.assertRaises(a.AdmissionError):
                lease.finish(reconciliation_complete=True)
            with self.assertRaises(a.AdmissionError):
                lease.reconcile_resource("container", "a" * 64, outcome="retained", size_bytes=100)
            lease.reconcile_resource("container", "a" * 64)
            lease.reconcile_resource("image", "sha256:" + "b" * 64, outcome="retained", size_bytes=100)
            lease.set_phase("provisioning")
            lease.set_phase("validating")
            with self.assertRaises(a.AdmissionError):
                lease.set_phase("assembling")
            with self.assertRaises(a.AdmissionError):
                lease.finish()
            lease.finish(reconciliation_complete=True)
        record = read_json(self.root / "admission.json")
        self.assertEqual(record, read_json(self.root / "history" / (lease.run_id + ".json")))
        with self.assertRaises(a.AdmissionError):
            with self.lease(lease.run_id):
                pass

    def test_interrupted_finalization_before_archive_or_current_commit_stays_blocking(self):
        for fail_target in ("archive", "current"):
            root = self.root / fail_target
            lease = a.AdmissionLease(root, str(uuid4()), SHA, collector=lambda _: observed(), allow_synthetic=True)
            with lease:
                original = a._sync_json
                def fail(path, value):
                    if fail_target == "archive" and path.parent.name == "history" or fail_target == "current" and path.name == "admission.json":
                        raise OSError("Synthetic interrupted finalization")
                    return original(path, value)
                with patch.object(a, "_sync_json", side_effect=fail), self.assertRaises(OSError):
                    lease.finish(reconciliation_complete=True)
            self.assertEqual(read_json(root / "admission.json")["state"], "active")
            with self.assertRaises(a.AdmissionError):
                with a.AdmissionLease(root, str(uuid4()), SHA, collector=lambda _: observed(), allow_synthetic=True):
                    pass

    def test_insufficient_capacity_or_synthetic_without_opt_in_never_reserves(self):
        bad = observed()
        bad["memory_available_bytes"] = 1
        measured = observed()
        measured["synthetic"] = False
        for name, options, code in (("capacity", {"collector": lambda _: bad, "allow_synthetic": True}, "capacity_refused"),
                                    ("synthetic", {"collector": lambda _: measured, "allow_synthetic": True}, "synthetic_observation")):
            root = self.root / name
            with self.assertRaises(a.AdmissionError) as error:
                with a.AdmissionLease(root, str(uuid4()), SHA, **options):
                    pass
            self.assertEqual(error.exception.code, code)
            self.assertFalse((root / "admission.json").exists())

    def test_malformed_archive_symlink_and_unowned_roots_cannot_authorize_admission(self):
        with self.lease() as lease:
            lease.finish(reconciliation_complete=True)
        archive = self.root / "history" / (lease.run_id + ".json")
        archive.unlink()  # Disposable corruption fixture, never a recovery operation.
        with self.assertRaises((a.AdmissionError, RunError, OSError)):
            with self.lease():
                pass
        link = Path(self.temporary.name) / "linked-root"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises((a.AdmissionError, RunError)):
            a.AdmissionLease(link, str(uuid4()), SHA)
        unowned = Path(self.temporary.name) / "unowned"
        unowned.mkdir(mode=0o700)
        (unowned / "unrelated.txt").write_text("Preserve this fixture")
        with self.assertRaises(a.AdmissionError):
            with a.AdmissionLease(unowned, str(uuid4()), SHA, collector=lambda _: observed(), allow_synthetic=True):
                pass
        self.assertEqual((unowned / "unrelated.txt").read_text(), "Preserve this fixture")

    def test_resume_requires_existing_owned_root_lock_marker_history_and_journal_without_initialization(self):
        missing = Path(self.temporary.name) / "never-initialized"
        with self.assertRaises((a.AdmissionError, RunError, OSError)):
            with a.AdmissionLease.resume(missing, str(uuid4()), SHA, allow_synthetic=True):
                pass
        self.assertFalse(missing.exists())
        for component in ("infrastructure.lock", "owner.json", "history", "admission.json"):
            root = Path(self.temporary.name) / component.replace(".", "-")
            with a.AdmissionLease(root, str(uuid4()), SHA, collector=lambda _: observed(), allow_synthetic=True) as lease:
                identifier = lease.run_id
            path = root / component
            if path.is_dir():
                path.rmdir()  # Disposable empty fixture, never operator state.
            else:
                path.unlink()
            before = {x.relative_to(root): x.read_bytes() for x in root.rglob("*") if x.is_file()}
            with self.subTest(missing=component), self.assertRaises((a.AdmissionError, RunError, OSError)):
                with a.AdmissionLease.resume(root, identifier, SHA, allow_synthetic=True):
                    pass
            self.assertFalse(path.exists())
            self.assertEqual(before, {x.relative_to(root): x.read_bytes() for x in root.rglob("*") if x.is_file()})

    def test_resume_requires_exact_current_run_source_profile_and_synthetic_mode(self):
        with self.lease() as original:
            identifier = original.run_id
        journal = self.root / "admission.json"
        before = journal.read_bytes()
        cases = ((str(uuid4()), SHA, "smoke", True), (identifier, "b" * 40, "smoke", True),
                 (identifier, SHA, "five-targets", True), (identifier, SHA, "smoke", False))
        for run, source, profile, synthetic in cases:
            with self.subTest(case=(run, source, profile, synthetic)), self.assertRaises(a.AdmissionError):
                with a.AdmissionLease.resume(self.root, run, source, profile, allow_synthetic=synthetic):
                    pass
            self.assertEqual(journal.read_bytes(), before)
        with self.resume(identifier):
            pass
        self.assertEqual(journal.read_bytes(), before)
        self.assertEqual(read_json(journal)["state"], "active")

    def test_resume_does_not_measure_allocate_register_adopt_or_complete_unknown_intent(self):
        with self.lease() as lease:
            lease.set_phase("assembling")
            lease.register_resource("container", "a" * 64)
            identifier = lease.run_id
        before = read_json(self.root / "admission.json")
        with patch.object(a, "build_plan", side_effect=AssertionError("No capacity refresh during cleanup")), \
             patch.object(a, "_read_command", side_effect=AssertionError("No Docker observations from resume")):
            with self.resume(identifier) as resumed:
                self.assertEqual(resumed.plan, before["plan"])
                for operation in (lambda: resumed.set_phase("assembling"), lambda: resumed.set_phase("materializing"),
                                  lambda: resumed.set_phase("provisioning"), lambda: resumed.set_phase("validating"),
                                  resumed.refresh, lambda: resumed.register_resource("container", "b" * 64)):
                    with self.assertRaises(a.AdmissionError) as error:
                        operation()
                    self.assertEqual(error.exception.code, "reconciliation_only")
                with self.assertRaises(a.AdmissionError):
                    resumed.reconcile_resource("container", "b" * 64)
                with self.assertRaises(a.AdmissionError) as error:
                    resumed.finish(reconciliation_complete=True)
                self.assertEqual(error.exception.code, "unreconciled_resources")
                resumed.set_phase("reconciling")
                resumed.reconcile_resource("container", "a" * 64)
                with self.assertRaises(a.AdmissionError):
                    resumed.finish()
        # No automatic completion even after every recorded resource was reconciled.
        self.assertEqual(read_json(self.root / "admission.json")["state"], "active")
        with self.resume(identifier) as resumed:
            self.assertEqual(resumed.plan, before["plan"])
            resumed.finish(reconciliation_complete=True)
        # A matching archived completion is idempotent, but still requires confirmation.
        final = (self.root / "admission.json").read_bytes()
        with self.resume(identifier) as resumed:
            with self.assertRaises(a.AdmissionError):
                resumed.finish()
            resumed.finish(reconciliation_complete=True)
        self.assertEqual((self.root / "admission.json").read_bytes(), final)

    def test_empty_uncertain_materialization_stays_active_until_adapter_explicitly_confirms(self):
        with self.lease() as lease:
            lease.set_phase("assembling")
            lease.set_phase("materializing")
            identifier = lease.run_id
        before = (self.root / "admission.json").read_bytes()
        with self.resume(identifier) as resumed:
            self.assertEqual(resumed.record["resources"], [])
            with self.assertRaises(a.AdmissionError):
                resumed.finish()
        self.assertEqual((self.root / "admission.json").read_bytes(), before)
        with self.assertRaises(a.AdmissionError):
            with self.lease():
                pass
        # Only an adapter that independently proves the uncertain daemon outcome may do this.
        with self.resume(identifier) as resumed:
            resumed.finish(reconciliation_complete=True)

    def test_resume_uses_same_exclusive_flock_and_cannot_take_over_a_live_process(self):
        with self.lease() as lease:
            identifier = lease.run_id
            code = "from wormhole.admission import AdmissionLease,AdmissionError;\ntry:\n with AdmissionLease.resume(sys.argv[1],sys.argv[2],'a'*40,allow_synthetic=True): pass\nexcept AdmissionError as e: print(e.code)"
            process = self.child(code, self.root, identifier)
            output, error = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, error)
            self.assertEqual(output.strip(), "infrastructure_busy")
        inode = (self.root / "infrastructure.lock").stat().st_ino
        with self.resume(identifier):
            process = self.child(code, self.root, identifier)
            output, error = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, error)
            self.assertEqual(output.strip(), "infrastructure_busy")
        self.assertEqual((self.root / "infrastructure.lock").stat().st_ino, inode)

    def test_resume_finishes_interrupted_archive_first_commit_without_replacing_archive(self):
        with self.lease() as lease:
            identifier = lease.run_id
            original = a._sync_json
            def fail_current(path, value):
                if path.name == "admission.json":
                    raise OSError("Synthetic failure after archive commit")
                return original(path, value)
            with patch.object(a, "_sync_json", side_effect=fail_current), self.assertRaises(OSError):
                lease.finish(reconciliation_complete=True)
            self.assertEqual(lease.record["state"], "active")
            for operation in (lambda: lease.set_phase("assembling"), lease.refresh,
                              lambda: lease.register_resource("container", "b" * 64)):
                with self.assertRaises(a.AdmissionError) as error:
                    operation()
                self.assertEqual(error.exception.code, "finalization_pending")
        archive = self.root / "history" / (identifier + ".json")
        archived = archive.read_bytes()
        before = (self.root / "admission.json").read_bytes()
        with self.resume(identifier) as resumed:
            for operation in (lambda: resumed.set_phase("reconciling"),
                              lambda: resumed.reconcile_resource("container", "a" * 64), resumed.finish):
                with self.assertRaises(a.AdmissionError):
                    operation()
        self.assertEqual((self.root / "admission.json").read_bytes(), before)
        with self.resume(identifier) as resumed:
            resumed.finish(reconciliation_complete=True)
        self.assertEqual(archive.read_bytes(), archived)
        self.assertEqual(read_json(self.root / "admission.json"), read_json(archive))
        with self.lease() as next_lease:
            next_lease.finish(reconciliation_complete=True)

    def test_resume_refuses_mismatched_or_missing_completion_archive_and_forked_use(self):
        with self.lease() as lease:
            identifier = lease.run_id
            lease.finish(reconciliation_complete=True)
        archive = self.root / "history" / (identifier + ".json")
        value = read_json(archive)
        value["source_revision"] = "b" * 40
        a._sync_json(archive, value)  # Disposable corruption fixture.
        before = (self.root / "admission.json").read_bytes()
        with self.assertRaises(a.AdmissionError) as error:
            with self.resume(identifier):
                pass
        self.assertEqual(error.exception.code, "invalid_archive")
        self.assertEqual((self.root / "admission.json").read_bytes(), before)
        archive.unlink()
        with self.assertRaises(a.AdmissionError):
            with self.resume(identifier):
                pass
        # A resumed descriptor, like an ordinary lease, belongs only to its acquiring process.
        other = Path(self.temporary.name) / "fork-fixture"
        with a.AdmissionLease(other, str(uuid4()), SHA, collector=lambda _: observed(), allow_synthetic=True) as lease:
            other_id = lease.run_id
        with a.AdmissionLease.resume(other, other_id, SHA, allow_synthetic=True) as resumed:
            with patch.object(a.os, "getpid", return_value=os.getpid() + 1), self.assertRaises(a.AdmissionError) as error:
                resumed.set_phase("reconciling")
            self.assertEqual(error.exception.code, "lease_owner_changed")


if __name__ == "__main__":
    unittest.main()
