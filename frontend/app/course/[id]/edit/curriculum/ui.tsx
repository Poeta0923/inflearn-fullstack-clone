"use client";

import type { Course, Lecture, Section } from "@/generated/openapi-client";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import * as api from "@/lib/api";
import { cn } from "@/lib/utils";
import {
  Check,
  GripVertical,
  Lock,
  LockOpen,
  Pencil,
  Plus,
  Trash2,
} from "lucide-react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

type CurriculumLecture = Pick<Lecture, "id" | "title" | "order" | "isPreview">;
type CurriculumSection = Pick<Section, "id" | "title" | "order"> & {
  lectures: CurriculumLecture[];
};

const buildInitialSections = (course: Course): CurriculumSection[] => {
  return [...(course.sections ?? [])]
    .sort((a, b) => a.order - b.order)
    .map((section) => ({
      id: section.id,
      title: section.title,
      order: section.order,
      lectures: [...(section.lectures ?? [])]
        .sort((a, b) => a.order - b.order)
        .map((lecture) => ({
          id: lecture.id,
          title: lecture.title,
          order: lecture.order,
          isPreview: lecture.isPreview,
        })),
    }));
};

export default function UI({ course }: { course: Course }) {
  const queryClient = useQueryClient();
  const courseQuery = useQuery<Course>({
    queryKey: ["course", course.id, "curriculum"],
    queryFn: async () => {
      const { data, error } = await api.getCourseById(
        course.id,
        "sections,lectures",
      );
      if (error || !data) {
        throw new Error("커리큘럼 정보를 불러오지 못했습니다.");
      }
      return data;
    },
    initialData: course,
  });

  const [sections, setSections] = useState<CurriculumSection[]>(() =>
    buildInitialSections(courseQuery.data),
  );
  const [isLectureDialogOpen, setIsLectureDialogOpen] = useState(false);
  const [targetSectionId, setTargetSectionId] = useState<string | null>(null);
  const [newLectureTitle, setNewLectureTitle] = useState("");

  useEffect(() => {
    setSections(buildInitialSections(courseQuery.data));
  }, [courseQuery.data]);

  const createSectionMutation = useMutation({
    mutationFn: async (payload: { title: string; order: number }) => {
      const { data, error } = await api.createSection(course.id, payload);
      if (error) {
        toast.error(error as string);
        return null;
      }

      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["course", course.id, "curriculum"],
      });
    },
  });

  const deleteSectionMutation = useMutation({
    mutationFn: async (payload: { sectionId: string }) => {
      const { data, error } = await api.deleteSection(payload.sectionId);
      if (error) {
        toast.error(error as string);
        return null;
      }
      return payload;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["course", course.id, "curriculum"],
      });
    },
  });

  const updateSectionMutation = useMutation({
    mutationFn: async (payload: { sectionId: string; title: string }) => {
      const { data, error } = await api.updateSection(
        payload.sectionId,
        payload.title,
      );
      if (error) {
        toast.error(error as string);
        return null;
      }
      return payload;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["course", course.id, "curriculum"],
      });
    },
  });

  const createLectureMutation = useMutation({
    mutationFn: async (payload: {
      sectionId: string;
      title: string;
      order: number;
    }) => {
      const { data, error } = await api.createLecture(
        payload.sectionId,
        payload.title,
      );
      if (error) {
        toast.error(error as string);
        return null;
      }

      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["course", course.id, "curriculum"],
      });
    },
  });

  const updateLectureTitleMutation = useMutation({
    mutationFn: async (payload: { lectureId: string; title: string }) => {
      const { data, error } = await api.updateLectureTitle(
        payload.lectureId,
        payload.title,
      );
      if (error) {
        toast.error(error as string);
        return null;
      }
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["course", course.id, "curriculum"],
      });
    },
  });

  const updateLectureOptionMutation = useMutation({
    mutationFn: async (payload: { lectureId: string; isPreview: boolean }) => {
      const { data, error } = await api.updateLectureOption(
        payload.lectureId,
        payload.isPreview,
      );
      if (error) {
        toast.error(error as string);
        return null;
      }
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["course", course.id, "curriculum"],
      });
    },
  });

  const deleteLectureMutation = useMutation({
    mutationFn: async (payload: { sectionId: string; lectureId: string }) => {
      const {data, error} = await api.deleteLecture(payload.lectureId);
      if (error) {
        toast.error(error as string);
        return null;
      }
      return payload;
    },
    onSuccess: () => {
      // TODO: 삭제 성공 시 로컬 상태 보정
      queryClient.invalidateQueries({
        queryKey: ["course", course.id, "curriculum"],
      });
    },
  });

  const targetSection = useMemo(
    () => sections.find((section) => section.id === targetSectionId),
    [sections, targetSectionId],
  );

  const addSection = () => {
    const nextOrder = sections.length + 1;
    const newSection: CurriculumSection = {
      id: `temp-section-${Date.now()}`,
      title: `섹션 ${nextOrder}`,
      order: nextOrder,
      lectures: [],
    };

    setSections((prev) => [...prev, newSection]);
    createSectionMutation.mutate({
      title: newSection.title,
      order: newSection.order,
    });
  };

  const deleteSection = (sectionId: string) => {
    setSections((prev) =>
      prev
        .filter((section) => section.id !== sectionId)
        .map((section, index) => ({ ...section, order: index + 1 })),
    );
    deleteSectionMutation.mutate({ sectionId });
  };

  const updateSectionTitle = (sectionId: string, title: string) => {
    setSections((prev) =>
      prev.map((section) =>
        section.id === sectionId ? { ...section, title } : section,
      ),
    );
  };

  const commitSectionTitle = (sectionId: string, title: string) => {
    updateSectionMutation.mutate({ sectionId, title });
  };

  const openLectureDialog = (sectionId: string) => {
    setTargetSectionId(sectionId);
    setNewLectureTitle("");
    setIsLectureDialogOpen(true);
  };

  const addLecture = () => {
    if (!targetSectionId || !newLectureTitle.trim()) {
      return;
    }

    setSections((prev) =>
      prev.map((section) => {
        if (section.id !== targetSectionId) {
          return section;
        }

        const newLecture: CurriculumLecture = {
          id: `temp-lecture-${Date.now()}`,
          title: newLectureTitle.trim(),
          order: section.lectures.length + 1,
          isPreview: false,
        };

        return { ...section, lectures: [...section.lectures, newLecture] };
      }),
    );

    setIsLectureDialogOpen(false);
    setNewLectureTitle("");
    setTargetSectionId(null);
    createLectureMutation.mutate({
      sectionId: targetSectionId,
      title: newLectureTitle.trim(),
      order: (targetSection?.lectures.length ?? 0) + 1,
    });
  };

  const updateLectureTitle = (
    sectionId: string,
    lectureId: string,
    title: string,
  ) => {
    setSections((prev) =>
      prev.map((section) => {
        if (section.id !== sectionId) {
          return section;
        }

        return {
          ...section,
          lectures: section.lectures.map((lecture) =>
            lecture.id === lectureId ? { ...lecture, title } : lecture,
          ),
        };
      }),
    );
  };

  const commitLectureTitle = (lectureId: string, title: string) => {
    updateLectureTitleMutation.mutate({ lectureId, title });
  };

  const deleteLecture = (sectionId: string, lectureId: string) => {
    setSections((prev) =>
      prev.map((section) => {
        if (section.id !== sectionId) {
          return section;
        }

        return {
          ...section,
          lectures: section.lectures
            .filter((lecture) => lecture.id !== lectureId)
            .map((lecture, index) => ({ ...lecture, order: index + 1 })),
        };
      }),
    );
    deleteLectureMutation.mutate({ sectionId, lectureId });
  };

  const toggleLecturePreview = (sectionId: string, lectureId: string) => {
    const currentLecture = sections
      .find((section) => section.id === sectionId)
      ?.lectures.find((lecture) => lecture.id === lectureId);
    const nextIsPreview = !(currentLecture?.isPreview ?? false);

    setSections((prev) =>
      prev.map((section) => {
        if (section.id !== sectionId) {
          return section;
        }

        return {
          ...section,
          lectures: section.lectures.map((lecture) =>
            lecture.id === lectureId
              ? { ...lecture, isPreview: !lecture.isPreview }
              : lecture,
          ),
        };
      }),
    );
    updateLectureOptionMutation.mutate({
      lectureId,
      isPreview: nextIsPreview,
    });
  };

  const openLectureEditModal = (_lectureId: string) => {
    // TODO: 강의 수정 모달 구현 예정
  };

  return (
    <div className="space-y-6">
      <div className="rounded-xl bg-white p-6">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-3xl font-bold text-gray-900">커리큘럼</h2>
          <Button variant="outline" onClick={addSection}>
            <Plus className="mr-1 h-4 w-4" />
            섹션 추가
          </Button>
        </div>
      </div>

      {sections.map((section) => (
        <section
          key={section.id}
          className="rounded-xl border border-gray-200 bg-white p-6"
        >
          <div className="mb-4 flex items-center gap-3">
            <span className="text-sm font-semibold text-emerald-600">{`섹션 ${section.order + 1}`}</span>
            <Button
              type="button"
              size="sm"
              variant="ghost"
              className="text-red-500 hover:text-red-600"
              onClick={() => deleteSection(section.id)}
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>

          <Input
            value={section.title}
            onChange={(event) =>
              updateSectionTitle(section.id, event.target.value)
            }
            onBlur={(event) =>
              commitSectionTitle(section.id, event.target.value)
            }
            placeholder="섹션 제목을 입력해주세요."
            className="mb-5 text-lg font-semibold"
          />

          {section.lectures.length === 0 ? (
            <div className="mb-5 rounded-lg border border-dashed border-gray-300 py-14 text-center text-gray-400">
              수업을 추가해 주세요.
            </div>
          ) : (
            <div className="mb-5 space-y-3">
              {section.lectures.map((lecture) => (
                <div
                  key={lecture.id}
                  className="flex items-center gap-3 rounded-lg border border-gray-200 bg-white px-4 py-3"
                >
                  <span className="w-6 text-center font-semibold text-gray-500">
                    {lecture.order + 1}
                  </span>
                  <Input
                    value={lecture.title}
                    onChange={(event) =>
                      updateLectureTitle(
                        section.id,
                        lecture.id,
                        event.target.value,
                      )
                    }
                    onBlur={(event) =>
                      commitLectureTitle(lecture.id, event.target.value)
                    }
                    className="flex-1 border-none p-0 text-base shadow-none focus-visible:ring-0"
                  />

                  <Button
                    type="button"
                    size="icon-sm"
                    variant="ghost"
                    onClick={() => toggleLecturePreview(section.id, lecture.id)}
                    title={
                      lecture.isPreview ? "미리보기 허용" : "미리보기 비허용"
                    }
                  >
                    {lecture.isPreview ? (
                      <LockOpen className="h-4 w-4 text-emerald-600" />
                    ) : (
                      <Lock className="h-4 w-4 text-gray-400" />
                    )}
                  </Button>

                  <Button
                    type="button"
                    size="icon-sm"
                    variant="ghost"
                    onClick={() => openLectureEditModal(lecture.id)}
                    title="강의 수정"
                  >
                    <Pencil className="h-4 w-4 text-gray-600" />
                  </Button>

                  <Button
                    type="button"
                    size="icon-sm"
                    variant="ghost"
                    onClick={() => deleteLecture(section.id, lecture.id)}
                    title="강의 삭제"
                  >
                    <Trash2 className="h-4 w-4 text-red-500" />
                  </Button>
                </div>
              ))}
            </div>
          )}

          <div className="flex items-center gap-3">
            <Button
              type="button"
              variant="secondary"
              onClick={() => openLectureDialog(section.id)}
            >
              <Plus className="h-4 w-4" />
              수업 추가
            </Button>
          </div>
        </section>
      ))}

      <Dialog open={isLectureDialogOpen} onOpenChange={setIsLectureDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {targetSection
                ? `${targetSection.title}에 수업 추가`
                : "수업 추가"}
            </DialogTitle>
          </DialogHeader>

          <div className="space-y-2">
            <p className="text-sm font-medium text-gray-700">수업 제목</p>
            <Input
              value={newLectureTitle}
              onChange={(event) => setNewLectureTitle(event.target.value)}
              placeholder="수업 제목을 입력해주세요."
            />
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setIsLectureDialogOpen(false)}
            >
              취소
            </Button>
            <Button
              type="button"
              onClick={addLecture}
              disabled={!newLectureTitle.trim()}
              className={cn(!newLectureTitle.trim() && "cursor-not-allowed")}
            >
              추가하기
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
