package db

import "testing"

// Exercise the real startup seed after both UI update paths. Disabled defaults
// must stay off, and both agent-side and skill-side reads must hide off rows.
func TestBuiltinSkillVisibilityPreservesExplicitDisable(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	a, err := d.GetAgentByKey("worker")
	if err != nil || a == nil {
		t.Fatalf("worker: %v", err)
	}
	type binding struct {
		name string
		on   bool
	}
	rows, err := d.Query(`SELECT skill_name,enabled FROM agent_skill_visibility WHERE agent_id=$1`, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	var original []binding
	for rows.Next() {
		var b binding
		if err := rows.Scan(&b.name, &b.on); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		original = append(original, b)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	rows.Close()
	defer func() {
		if _, err := d.Exec(`DELETE FROM agent_skill_visibility WHERE agent_id=$1`, a.ID); err != nil {
			t.Error(err)
		}
		for _, b := range original {
			if err := d.ToggleSkillVisibility(a.ID, b.name, b.on); err != nil {
				t.Error(err)
			}
		}
	}()
	for _, path := range []string{"bulk", "toggle"} {
		t.Run(path, func(t *testing.T) {
			if err := d.ToggleSkillVisibility(a.ID, "api-recon", true); err != nil {
				t.Fatal(err)
			}
			if path == "bulk" {
				err = d.SetAgentSkillVisibility(a.ID, []string{"tooling-restart-fixture"})
			} else {
				err = d.ToggleSkillVisibility(a.ID, "api-recon", false)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := d.seedBuiltinSkillVisibility(); err != nil {
				t.Fatal(err)
			}
			names, err := d.AgentSkillNames(a.ID)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range names {
				if name == "api-recon" {
					t.Fatal("startup restored a disabled skill")
				}
			}
			ids, err := d.SkillAgents("api-recon")
			if err != nil {
				t.Fatal(err)
			}
			for _, id := range ids {
				if id == a.ID {
					t.Fatal("skill-side read exposed a disabled binding")
				}
			}
			if err := d.ToggleSkillVisibility(a.ID, "api-recon", true); err != nil {
				t.Fatal(err)
			}
			var on bool
			if err := d.QueryRow(`SELECT enabled FROM agent_skill_visibility WHERE agent_id=$1 AND skill_name='api-recon'`, a.ID).Scan(&on); err != nil || !on {
				t.Fatalf("re-enable: %v, enabled=%v", err, on)
			}
		})
	}
}
