import { DateTime, DurationLike } from 'luxon';

export type TimeUnit = 'DAYS' | 'WEEKS' | 'MONTHS' | 'YEARS' | 'TRIMESTERS';

/**
 * Add an interval to either the current time or an input time.
 * Interval format is nnnx where nnn is a positive integer
 * and x is one of the following interval period.
 *    s: seconds
 *    m: minutes
 *    h: hours
 *    d: days
 * @param interval - Interval of time to add.
 * @param dateValue - Optional date value to add the interval to.
 * @returns - The new date value.
 */
export function createInterval(
  interval: string,
  dateValue = currentTimeStamp(),
): Date {
  const value = parseInt(interval.slice(0, -1));
  if (isNaN(value) || value <= 0) {
    throw new Error('Invalid interval value');
  }
  let duration: DurationLike;
  const intervalPeriod = interval.at(-1)?.toLowerCase();
  switch (intervalPeriod) {
    case 's':
      duration = { seconds: value };
      break;

    case 'm':
      duration = { minutes: value };
      break;

    case 'h':
      duration = { hours: value };
      break;

    case 'd':
      duration = { days: value };
      break;

    default:
      throw new Error('Invalid interval period');
  }
  const newDate = DateTime.fromJSDate(dateValue).plus(duration);
  return new Date(newDate.valueOf());
}

export function isExpired(date: Date): boolean {
  const now = currentTimeStamp();
  return date < now;
}

export function currentTimeStamp(): Date {
  return new Date(DateTime.now().valueOf());
}

export function isDateWithinThreshold(
  date: Date | string,
  threshold = 1,
  unit: TimeUnit = 'MONTHS',
): boolean {
  const inputDate = new Date(date);
  const now = new Date();

  if (isNaN(inputDate.getTime())) {
    throw new Error('Invalid date provided.');
  }

  const diffMs = now.getTime() - inputDate.getTime();
  const msPerUnit: Record<TimeUnit, number> = {
    DAYS: 1000 * 60 * 60 * 24,
    WEEKS: 1000 * 60 * 60 * 24 * 7,
    MONTHS: 1000 * 60 * 60 * 24 * 30,
    TRIMESTERS: 1000 * 60 * 60 * 24 * 30 * 3,
    YEARS: 1000 * 60 * 60 * 24 * 365,
  };

  const unitMs = msPerUnit[unit];
  return diffMs <= threshold * unitMs;
}

export function minutesSince(date: Date | string) {
  const lastDate = new Date(date);
  const now = new Date();
  const diffMs = now.getMilliseconds() - lastDate.getMilliseconds();
  return Math.floor(diffMs / 60_000);
}
