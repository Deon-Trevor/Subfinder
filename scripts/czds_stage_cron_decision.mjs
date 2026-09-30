export function needsStageCron(jobs) {
  if (jobs.length > 1) throw new Error("multiple CZDS jobs appeared after deploy");
  return jobs.length === 0;
}
